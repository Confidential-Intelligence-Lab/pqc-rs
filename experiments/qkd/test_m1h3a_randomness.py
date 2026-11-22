import json
import unittest

from m1h3a_randomness import (
    RandomnessConfiguration, RandomnessError, RandomnessStreams,
    report, simulate_records,
)


def ideal(bit, preparation, measurement):
    return bit if preparation == measurement else 0


def run(mode="fixture", seed=20261120, n_z=20, k_x=20, cap=500, measure=ideal):
    rng = RandomnessStreams(RandomnessConfiguration(mode, seed))
    a, b = simulate_records(n_z=n_z, k_x=k_x, max_transmissions=cap,
                            randomness=rng, measure=measure)
    return a, b, report(a, b, rng, n_z, k_x)


class H3ARandomnessTests(unittest.TestCase):
    def test_fixture_reproducibility(self):
        self.assertEqual(run(), run())

    def test_domain_separation(self):
        rng = RandomnessStreams(RandomnessConfiguration("fixture", 42))
        sequence = {name: tuple(rng.randbelow(name, 1 << 30) for _ in range(10))
                    for name in ("alice_bits", "alice_bases", "bob_bases", "eve", "sampling")}
        self.assertEqual(len(set(sequence.values())), 5)

    def test_fixture_seed_is_required(self):
        for seed in (None, -1, True, 2.5):
            with self.assertRaises(RandomnessError):
                RandomnessStreams(RandomnessConfiguration("fixture", seed))

    def test_os_mode_rejects_seed(self):
        with self.assertRaises(RandomnessError):
            RandomnessStreams(RandomnessConfiguration("os", 0))

    def test_os_mode_uses_cryptographic_source(self):
        _, _, r = run(mode="os", seed=None)
        self.assertTrue(r["source_randomness_os_backed"])
        self.assertFalse(r["private_independence_theorem_assumptions_verified"])
        self.assertFalse(r["security_qualified"])

    def test_no_secrets_or_seed_in_report(self):
        a, b, r = run(seed=987654321)
        output = json.dumps(r)
        self.assertNotIn("987654321", output)
        self.assertNotIn("raw_key", output)
        self.assertNotIn("alice_bits", output)
        self.assertNotIn("source_bits", output)
        self.assertFalse(r["hpke_export_authorized"])
        self.assertEqual(len(a), len(b))

    def test_sampling_without_replacement(self):
        source = RandomnessStreams(RandomnessConfiguration("fixture", 55))
        indices = source.sample_indices(100, 37)
        self.assertEqual(len(indices), 37)
        self.assertEqual(len(set(indices)), 37)
        self.assertTrue(all(0 <= v < 100 for v in indices))

    def test_sample_invalid_ranges(self):
        source = RandomnessStreams(RandomnessConfiguration("os"))
        for n, k in ((-1, 0), (3, 4), (2, -1), (True, 1)):
            with self.assertRaises(RandomnessError):
                source.sample_indices(n, k)

    def test_reject_invalid_random_bound(self):
        source = RandomnessStreams(RandomnessConfiguration("os"))
        for value in (0, -1, 1.2, False):
            with self.assertRaises(RandomnessError):
                source.randbelow("eve", value)
        with self.assertRaises(RandomnessError):
            source.randbelow("unknown", 3)

    def test_quota_and_abort(self):
        _, _, full = run(n_z=12, k_x=9, cap=500)
        _, _, abort = run(n_z=12, k_x=9, cap=21)
        self.assertEqual(full["decision"], "QUOTAS_MET")
        self.assertEqual(full["z_accepted"], 12)
        self.assertEqual(full["x_accepted"], 9)
        self.assertEqual(abort["decision"], "ABORT_MAX_TRANSMISSIONS")

    def test_measurement_corruption_rejected(self):
        with self.assertRaises(RandomnessError):
            run(measure=lambda *_: 3)

    def test_invalid_simulator_parameters(self):
        rng = RandomnessStreams(RandomnessConfiguration("fixture", 5))
        for kw in ({"n_z": 0}, {"z_probability": float("nan")},
                   {"max_transmissions": 100001}, {"intercept_percent": 101}):
            args = dict(n_z=10, k_x=10, max_transmissions=200,
                        randomness=rng, measure=ideal)
            args.update(kw)
            with self.assertRaises(RandomnessError):
                simulate_records(**args)


if __name__ == "__main__":
    unittest.main()
