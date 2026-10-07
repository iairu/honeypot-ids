"""Reconcile-loop test against a real Redis with Docker stubbed out.

Needs a Redis reachable at $REDIS_TEST_HOST (password $REDIS_TEST_PASSWORD, or
none); skipped otherwise. Example:
  docker run -d --rm --name r -p 6390:6379 redis:7-alpine
  REDIS_TEST_HOST=127.0.0.1 REDIS_TEST_PORT=6390 python -m unittest test_manager_reconcile
"""
import os
import sys
import time
import types
import unittest
from unittest import mock

HOST = os.environ.get("REDIS_TEST_HOST")

# manager.py imports docker/redis at module level; stub docker so the test also
# runs where the SDK isn't installed.
sys.modules.setdefault("docker", mock.MagicMock())


@unittest.skipUnless(HOST, "REDIS_TEST_HOST not set")
class Reconcile(unittest.TestCase):
    STATIC = 3           # compose-declared pools (WordPress layer)

    def setUp(self):
        import redis
        os.environ.setdefault("REDIS_PASSWORD", "x")
        os.environ.setdefault("MYSQL_PASSWORD", "x")
        import manager
        self.m = manager
        manager.STATIC_COUNT = self.STATIC
        manager.MAX_POOLS = 10
        manager.MAX_MEMORY_MB = 0
        manager.MAX_CPUS = 0
        manager.SPARES = 1
        manager.PARALLEL_BUILDS = 2
        self.r = redis.Redis(host=HOST, port=int(os.environ.get("REDIS_TEST_PORT", "6379")),
                             decode_responses=True)
        self.r.flushall()
        with mock.patch.object(manager.Manager, "__init__", lambda s: None):
            self.mgr = manager.Manager()
        self.mgr.redis = self.r
        self.mgr.in_flight = set()
        self.mgr.backoff_until = 0.0
        self.mgr.docker = mock.MagicMock()
        self.mgr.static_pool_up = lambda n: True
        self.mgr.runtime_pools = lambda: set()
        self.mgr.pool_container_healthy = lambda n: True
        self.started = []

        # Builds finish when finish_builds() is called (synchronously).
        self.building = []

        def fake_start(n):
            self.started.append(n)
            self.mgr.in_flight.add(n)
            self.building.append(n)
        self.mgr.start_build = fake_start
        self.mgr.can_grow = lambda: (True, "")
        self.mgr.destroyed = []
        self.mgr.destroy = lambda n: (self.mgr.destroyed.append(n), self.mgr.unregister(n))

    def run_reconcile(self, finish=True):
        self.mgr.reconcile()
        if finish:
            self.finish_builds()

    def finish_builds(self):
        while self.building:
            n = self.building.pop(0)
            self.mgr.register_ready(n)
            self.mgr.in_flight.discard(n)

    def static_ids(self):
        return [str(i) for i in range(1, self.STATIC + 1)]

    def test_adopts_static_pools_as_free_then_builds_no_spare(self):
        self.run_reconcile()
        self.assertEqual(self.r.smembers(self.m.READY_KEY), set(self.static_ids()))
        self.assertEqual(self.r.zcard(self.m.FREE_KEY), self.STATIC)
        self.assertEqual(self.started, [])          # spares already free

    def test_assignment_wakeup_builds_exactly_one_spare(self):
        self.run_reconcile()
        for n in self.static_ids():                 # every static pool owned
            self.own(n, f"10.0.0.{n}")
        self.r.rpush(self.m.PROVISION_KEY, "10.0.0.9")
        self.run_reconcile()
        first = str(self.STATIC + 1)
        self.assertEqual(self.started, [int(first)])
        self.assertEqual(self.r.zrange(self.m.FREE_KEY, 0, -1), [first])
        self.run_reconcile()                        # spare exists: nothing more
        self.assertEqual(self.started, [int(first)])
        self.assertEqual(self.r.llen(self.m.PROVISION_KEY), 0)

    def test_stops_at_max_pools(self):
        self.m.MAX_POOLS = self.STATIC
        self.run_reconcile()
        for n in self.static_ids():
            self.own(n, f"10.6.0.{n}")
        self.run_reconcile()
        self.assertEqual(self.started, [])

    def own(self, pool, ip, live=True):
        self.r.zrem(self.m.FREE_KEY, str(pool))
        self.r.sadd(self.m.OWNER_PREFIX + str(pool), ip)
        if live:
            self.r.set(self.m.SESSION_KEY_PREFIX + ip, str(pool))

    def test_low_host_resources_cap_growth(self):
        self.run_reconcile()
        for n in self.static_ids():
            self.own(n, f"10.1.0.{n}")
        self.mgr.can_grow = lambda: (False, "low memory: 100 MB available")
        self.r.rpush(self.m.PROVISION_KEY, "10.1.0.9")
        self.run_reconcile()
        self.assertEqual(self.started, [])
        self.assertIn("low memory", self.r.get(self.m.CAPPED_KEY))

    def test_idle_static_pool_is_reused_not_destroyed(self):
        self.run_reconcile()
        self.own(1, "10.2.0.1", live=False)            # assignment expired
        self.run_reconcile()
        self.assertEqual(self.mgr.destroyed, [])
        self.assertIn("1", self.r.zrange(self.m.FREE_KEY, 0, -1))
        self.assertEqual(self.r.scard(self.m.OWNER_PREFIX + "1"), 0)

    def test_live_owner_keeps_the_pool(self):
        self.run_reconcile()
        self.own(1, "10.3.0.1")
        self.run_reconcile()
        self.assertNotIn("1", self.r.zrange(self.m.FREE_KEY, 0, -1))

    def test_idle_runtime_pool_recycled_when_host_has_room(self):
        self.run_reconcile()
        n = self.STATIC + 1
        self.m.RECYCLE_IDLE = True
        self.mgr.register_ready(n, owned=True)
        self.own(n, "10.4.0.1", live=False)
        self.run_reconcile()
        self.assertEqual(self.mgr.destroyed, [n])

    def test_idle_runtime_pool_reused_when_host_is_loaded(self):
        self.run_reconcile()
        n = self.STATIC + 1
        self.m.RECYCLE_IDLE = True
        self.mgr.register_ready(n, owned=True)
        self.own(n, "10.5.0.1", live=False)
        self.mgr.can_grow = lambda: (False, "high load")
        self.run_reconcile()
        self.assertEqual(self.mgr.destroyed, [])
        self.assertIn(str(n), self.r.zrange(self.m.FREE_KEY, 0, -1))

    def assign(self, sid):
        """What pool_router does for a new session (ASSIGN_SCRIPT, via EVAL)."""
        script = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..",
                                   "reverse_proxy_enhanced", "lua", "pool_router_rules.lua")).read()
        script = script.split("_M.ASSIGN_SCRIPT = [[", 1)[1].split("]]", 1)[0]
        pool, mode = self.r.eval(script, 7, self.m.SESSION_KEY_PREFIX + sid, self.m.FREE_KEY,
                                 self.m.READY_KEY, "honeypot_pool:counter", self.m.PROVISION_KEY,
                                 self.m.CAPPED_KEY, self.m.WAITING_KEY, sid, 86400, 200)
        return int(pool), mode

    def test_scales_one_pool_per_waiting_session_and_hands_it_over(self):
        self.run_reconcile()
        for i in range(self.STATIC):
            self.assertEqual(self.assign(f"s{i}")[1], "exclusive")
        waiting = [f"w{i}" for i in range(3)]
        borrowed = {sid: self.assign(sid) for sid in waiting}
        self.assertTrue(all(m == "pending" for _p, m in borrowed.values()))
        self.run_reconcile(finish=False)
        self.assertEqual(len(self.started), 2)          # PARALLEL_BUILDS at a time
        self.finish_builds()
        self.run_reconcile()                            # remaining waiter + 1 spare
        self.run_reconcile()
        own = {sid: int(self.r.get(self.m.SESSION_KEY_PREFIX + sid)) for sid in waiting}
        self.assertEqual(len(set(own.values())), 3)
        self.assertTrue(all(p > self.STATIC for p in own.values()))
        for sid, p in own.items():
            self.assertEqual(self.r.smembers(self.m.OWNER_PREFIX + str(p)), {sid})
            self.assertNotIn(sid, self.r.smembers(self.m.OWNER_PREFIX + str(borrowed[sid][0])))
        self.assertEqual(self.r.zcard(self.m.WAITING_KEY), 0)
        self.assertEqual(self.r.zcard(self.m.FREE_KEY), 1)   # the spare
        self.assertGreater(self.r.ttl(self.m.SESSION_KEY_PREFIX + "w0"), 0)
        self.assertEqual(self.assign("w0"), (own["w0"], "existing"))

    def test_resource_budget_caps_scaling_then_round_robin(self):
        cost = self.m.POOL_MEM_MB
        self.m.MAX_MEMORY_MB = cost * (self.STATIC + 1)   # room for one more pool
        self.run_reconcile()
        for i in range(self.STATIC):
            self.assign(f"s{i}")
        for i in range(3):
            self.assign(f"w{i}")
        self.run_reconcile()
        self.run_reconcile()
        self.assertEqual(self.started, [self.STATIC + 1])
        self.assertIn("POOL_MAX_MEMORY_MB", self.r.get(self.m.CAPPED_KEY))
        self.assertEqual(int(self.r.get(self.m.SESSION_KEY_PREFIX + "w0")), self.STATIC + 1)
        self.assertEqual(self.r.zcard(self.m.WAITING_KEY), 0)  # the rest stay round-robin
        self.assertEqual(self.assign("late")[1], "shared")

    def test_expired_waiting_session_gets_no_pool(self):
        self.run_reconcile()
        for i in range(self.STATIC):
            self.assign(f"s{i}")
        self.assign("gone")
        self.r.delete(self.m.SESSION_KEY_PREFIX + "gone")
        self.run_reconcile()
        self.assertEqual(self.r.zcard(self.m.WAITING_KEY), 0)
        self.assertEqual(self.started, [self.STATIC + 1])   # just the spare


class ReconcileDatabaseLayer(Reconcile):
    """Database layer: only `honeypot_database` (pool 1) is compose-declared."""
    STATIC = 1


if __name__ == "__main__":
    unittest.main()
