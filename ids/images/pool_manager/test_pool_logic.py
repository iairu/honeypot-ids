import unittest

import pool_logic as pl


class NextPoolNumber(unittest.TestCase):
    def test_first_runtime_pool_is_four(self):
        self.assertEqual(pl.next_pool_number({1, 2, 3}), 4)

    def test_reuses_gaps(self):
        self.assertEqual(pl.next_pool_number({1, 2, 3, 4, 6}), 5)

    def test_ignores_static_numbers_missing(self):
        self.assertEqual(pl.next_pool_number(set()), 4)


class PoolsToStart(unittest.TestCase):
    def test_all_pools_owned_builds_one_spare(self):
        self.assertEqual(pl.pools_to_start(0, 0, 0, 1, room=10, parallel=3), 1)

    def test_a_free_pool_means_nothing_to_build(self):
        self.assertEqual(pl.pools_to_start(1, 0, 0, 1, room=10, parallel=3), 0)

    def test_in_flight_counts_as_a_spare(self):
        self.assertEqual(pl.pools_to_start(0, 1, 0, 1, room=10, parallel=3), 0)

    def test_scales_with_waiting_sessions_in_parallel(self):
        # 7 sessions waiting + 1 spare, nothing free: 3 builds at once.
        self.assertEqual(pl.pools_to_start(0, 0, 7, 1, room=10, parallel=3), 3)
        # 2 already building: one more slot.
        self.assertEqual(pl.pools_to_start(0, 2, 7, 1, room=10, parallel=3), 1)

    def test_never_exceeds_the_budget(self):
        self.assertEqual(pl.pools_to_start(0, 0, 7, 1, room=2, parallel=3), 2)
        self.assertEqual(pl.pools_to_start(0, 0, 7, 1, room=0, parallel=3), 0)


class BudgetRoom(unittest.TestCase):
    def test_memory_budget_limits_pool_count(self):
        # 12288 MB / 1536 MB = 8 pools; 3 exist -> 5 more.
        self.assertEqual(pl.budget_room(3, 1536, 1.5, 12288, 0, 10), (5, ""))

    def test_cpu_budget_limits_pool_count(self):
        self.assertEqual(pl.budget_room(3, 1536, 1.5, 0, 6, 10)[0], 1)

    def test_reports_the_limit_once_full(self):
        room, reason = pl.budget_room(8, 1536, 1.5, 12288, 0, 10)
        self.assertEqual(room, 0)
        self.assertIn("POOL_MAX_MEMORY_MB", reason)
        room, reason = pl.budget_room(4, 512, 0.5, 0, 2, 10)
        self.assertEqual(room, 0)
        self.assertIn("POOL_MAX_CPUS", reason)

    def test_zero_means_unlimited_but_pool_max_still_applies(self):
        self.assertEqual(pl.budget_room(3, 1536, 1.5, 0, 0, 10), (7, ""))
        room, reason = pl.budget_room(10, 1536, 1.5, 0, 0, 10)
        self.assertEqual(room, 0)
        self.assertIn("POOL_MAX=10", reason)

    def test_over_budget_is_zero_not_negative(self):
        self.assertEqual(pl.budget_room(5, 1536, 1.5, 3072, 0, 10)[0], 0)


class StaleOwners(unittest.TestCase):
    def test_expired_and_moved_owners_are_stale(self):
        owners = {"a", "b", "c"}
        got = pl.stale_owners(owners, {"a": 4, "b": None, "c": 5}, 4)
        self.assertEqual(got, {"b", "c"})

    def test_all_live(self):
        self.assertEqual(pl.stale_owners({"a"}, {"a": 4}, 4), set())


class HostPressure(unittest.TestCase):
    LIMITS = dict(min_free_mem_mb=2560, max_load_per_cpu=1.5, min_free_disk_gb=5)

    def check(self, mem=4000, load=1.0, cpus=4, disk=50):
        return pl.host_pressure(mem, load, cpus, disk, **self.LIMITS)

    def test_healthy_host(self):
        self.assertEqual(self.check(), "")

    def test_low_memory(self):
        self.assertIn("low memory", self.check(mem=1800))

    def test_high_load(self):
        self.assertIn("high load", self.check(load=7.0, cpus=4))

    def test_low_disk(self):
        self.assertIn("low disk", self.check(disk=2))

    def test_memory_reported_first(self):
        self.assertIn("low memory", self.check(mem=100, load=99, disk=0))


class IdleAction(unittest.TestCase):
    def test_recycles_runtime_pool_when_there_is_room(self):
        self.assertEqual(pl.idle_action(True, True, False), "recycle")

    def test_reuses_when_host_is_loaded(self):
        self.assertEqual(pl.idle_action(True, False, False), "reuse")

    def test_reuses_at_the_pool_ceiling(self):
        self.assertEqual(pl.idle_action(True, True, True), "reuse")

    def test_never_recycles_compose_pools(self):
        self.assertEqual(pl.idle_action(False, True, False), "reuse")


if __name__ == "__main__":
    unittest.main()
