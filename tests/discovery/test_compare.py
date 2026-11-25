import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("compare", Path(__file__).resolve().parents[2] / "tools/discovery_compare.py")
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


class ComparisonTests(unittest.TestCase):
    def test_false_positives_and_missed_hosts_are_separate(self):
        truth = {"192.0.2.1": True, "192.0.2.2": True, "192.0.2.3": False, "192.0.2.4": False}
        observations = {"192.0.2.1": True, "192.0.2.2": False, "192.0.2.3": True, "192.0.2.4": False}
        result = compare.evaluate(truth, observations)
        self.assertEqual(result["FalsePositiveIPs"], ["192.0.2.3"])
        self.assertEqual(result["FalseNegativeIPs"], ["192.0.2.2"])
        self.assertEqual(result["Precision"], .5)
        self.assertEqual(result["Recall"], .5)

    def test_missing_coverage_is_not_a_negative_result(self):
        with self.assertRaises(ValueError):
            compare.evaluate({"192.0.2.1": True}, {})

    def test_unknown_truth_and_duplicates_rejected(self):
        for rows in [
            [],
            [{"IP": "192.0.2.1", "Alive": "true"}],
            [{"IP": "192.0.2.1", "Alive": True}] * 2,
            [{"IP": 1, "Alive": True}],
            [{"IP": True, "Alive": True}],
        ]:
            with self.assertRaises(ValueError):
                compare.host_map(rows, "IP", "Alive")

    def test_no_positive_claims_does_not_mean_perfect_precision(self):
        result = compare.evaluate({"192.0.2.1": True}, {"192.0.2.1": False})
        self.assertIsNone(result["Precision"])
        self.assertEqual(result["Recall"], 0)

    def test_partial_report_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({"Completed": False, "Results": []}))
            with self.assertRaises(ValueError):
                compare.load_report(path)

    def test_unconfirmed_and_probe_error_not_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({"Completed": True, "Results": [{"IP": "192.0.2.1", "IsAlive": False, "Warnings": ["ping unavailable"]}]}))
            observations, metadata = compare.load_report(path)
            self.assertFalse(observations["192.0.2.1"])
            self.assertEqual(metadata["ProbeErrorIPs"], ["192.0.2.1"])

    def test_nmap_scope_and_completion_validation(self):
        xml = '<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/></host><runstats><finished exit="success"/><hosts up="1" total="2"/></runstats></nmaprun>'
        with tempfile.TemporaryDirectory() as directory:
            path, scope = Path(directory) / "scan.xml", Path(directory) / "scope.json"
            path.write_text(xml)
            scope.write_text('["192.0.2.1", "192.0.2.2"]')
            observations, _ = compare.load_nmap(path, scope)
            self.assertEqual(observations, {"192.0.2.1": True, "192.0.2.2": False})
            scope.write_text('["192.0.2.1"]')
            with self.assertRaises(ValueError):
                compare.load_nmap(path, scope)
            path.write_text(xml.replace('exit="success"', 'exit="error"'))
            with self.assertRaises(ValueError):
                compare.load_nmap(path, scope)


if __name__ == "__main__":
    unittest.main()
