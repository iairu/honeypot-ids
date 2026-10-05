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
        self.r = redis.Redis(host=HOST, port=int(os.environ.get("REDIS_TEST_PORT", "6379")),
                             decode_responses=True)
        self.r.flushall()
        with mock.patch.object(manager.Manager, "__init__", lambda s: None):
            self.mgr = manager.Manager()
        self.mgr.redis = self.r
        self.mgr.in_flight = None
        self.mgr.backoff_until = 0.0
        self.mgr.worker = None
        self.mgr.docker = mock.MagicMock()
        self.mgr.static_pool_up = lambda n: True
        self.mgr.runtime_pools = lambda: set()
        self.mgr.pool_container_healthy = lambda n: True
        self.started = []

        def fake_thread(n):
            self.started.append(n)
            self.mgr.register_ready(n)
            self.mgr.in_flight = None
        self.mgr._provision_thread = fake_thread
        self.mgr.can_grow = lambda: (True, "")
        self.mgr.destroyed = []
        self.mgr.destroy = lambda n: (self.mgr.destroyed.append(n), self.mgr.unregister(n))

    def run_reconcile(self):
        self.mgr.reconcile()
        if self.mgr.worker:
            self.mgr.worker.join(2)

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


class ReconcileDatabaseLayer(Reconcile):
    """Database layer: only `honeypot_database` (pool 1) is compose-declared."""
    STATIC = 1


if __name__ == "__main__":
    unittest.main()
