import unittest

import pool_logic as pl


class NextPoolNumber(unittest.TestCase):
    def test_first_runtime_pool_is_four(self):
        self.assertEqual(pl.next_pool_number({1, 2, 3}), 4)

    def test_reuses_gaps(self):
        self.assertEqual(pl.next_pool_number({1, 2, 3, 4, 6}), 5)

    def test_ignores_static_numbers_missing(self):
        self.assertEqual(pl.next_pool_number(set()), 4)


class SparesNeeded(unittest.TestCase):
    def test_all_pools_owned_builds_one(self):
        self.assertEqual(pl.spares_needed(0, 0, 1, 3, 10), 1)

    def test_a_free_pool_means_nothing_to_build(self):
        self.assertEqual(pl.spares_needed(1, 0, 1, 4, 10), 0)

    def test_in_flight_counts_as_a_spare(self):
        self.assertEqual(pl.spares_needed(0, 1, 1, 4, 10), 0)

    def test_never_exceeds_max(self):
        self.assertEqual(pl.spares_needed(0, 0, 1, 10, 10), 0)
        self.assertEqual(pl.spares_needed(0, 0, 3, 9, 10), 1)

    def test_in_flight_counts_against_max(self):
        self.assertEqual(pl.spares_needed(0, 1, 5, 9, 10), 0)


class StaleOwners(unittest.TestCase):
    def test_expired_and_moved_owners_are_stale(self):
        owners = {"a", "b", "c"}
        got = pl.stale_owners(owners, {"a": 4, "b": None, "c": 5}, 4)
        self.assertEqual(got, {"b", "c"})

    def test_all_live(self):
        self.assertEqual(pl.stale_owners({"a"}, {"a": 4}, 4), set())


if __name__ == "__main__":
    unittest.main()
