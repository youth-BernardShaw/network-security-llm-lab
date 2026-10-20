"""Statistical edge cases and source-to-deliverable integrity checks."""
import csv
import importlib.util
import json
import tempfile
from collections import Counter
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1]
ROOT = BASE.parent
spec = importlib.util.spec_from_file_location("analysis", BASE / "tools/build_analysis.py")
analysis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analysis)


class StatisticalRules(unittest.TestCase):
    def test_all_confusion_cells_and_unknown(self):
        self.assertEqual(analysis.classification("存在候选", "有漏洞"), "TP")
        self.assertEqual(analysis.classification("存在候选", "无所关注漏洞"), "FP")
        self.assertEqual(analysis.classification("未检出候选", "有漏洞"), "FN")
        self.assertEqual(analysis.classification("未检出候选", "无所关注漏洞"), "TN")
        self.assertEqual(analysis.classification("无法判定", "有漏洞"), "U")
        self.assertEqual(analysis.classification("存在候选", ""), "U")

    def test_zero_denominators_and_imbalanced_case(self):
        self.assertIsNone(analysis.ratio(0, 0))
        m = analysis.classification_metrics(Counter(TP=2, FP=1, FN=3, TN=4))
        self.assertEqual(m["precision"], (2, 3))
        self.assertEqual(m["recall"], (2, 5))
        self.assertEqual(m["f1"], (4, 8))
        self.assertEqual(m["false_positive_rate"], (1, 5))

    def test_empty_or_negative_evidence_not_vacuously_complete(self):
        self.assertEqual(analysis.field_completeness(
            {"verdict": "排除", "findings": [], "exclusion_evidence": []})["evidence_complete"], 0)
        self.assertFalse(analysis.nonempty_strings([]))
        self.assertFalse(analysis.nonempty_strings([""]))
        self.assertFalse(analysis.nonempty_strings("文字不能冒充数组"))


class DeliverableIntegrity(unittest.TestCase):
    def test_frozen_sources_unchanged(self):
        analysis.verify_sources()

    def test_84_outputs_are_exact_source_copies(self):
        rows = analysis.read_csv(BASE / "labeled_results.csv")
        self.assertEqual(len(rows), 84)
        for row in rows:
            original = ROOT / row["source_output"]
            copy = BASE / "raw_outputs" / row["cohort"] / (row["sample_id"] + ".json")
            self.assertEqual(original.read_bytes(), copy.read_bytes())
            self.assertEqual(analysis.sha(original.read_bytes()), row["output_sha256"])

    def test_primary_labels_condition_and_population(self):
        rows = [r for r in analysis.read_csv(BASE / "labeled_results.csv") if r["primary"] == "1"]
        self.assertEqual(len(rows), 42)
        for v in ("v1", "v2", "v3"):
            group = [r for r in rows if r["cohort"] == v]
            self.assertEqual(len({r["sample_id"] for r in group}), 14)
            self.assertEqual(Counter(r["classification"] for r in group), Counter(TP=12, TN=2))
            auth = next(r for r in group if r["sample_id"] == "AUTH-001")
            self.assertIn("security=low", auth["condition_key"])

    def test_poc_not_run_is_not_zero_success_rate(self):
        pocs = analysis.read_csv(BASE / "poc_execution.csv")
        primary = [p for p in pocs if p["cohort"] in ("v1", "v2", "v3")]
        self.assertEqual(len(primary), 40)
        self.assertTrue(all(p["execution_status"] == "not_run" and p["success"] == "" for p in primary))
        for r in analysis.read_csv(BASE / "metrics.csv"):
            if r["metric"] == "poc_runnable_rate":
                self.assertEqual(r["value"], "")
                self.assertEqual(r["numerator"], "")
                self.assertEqual(r["status"], "not_measured")

    def test_input_hash_algorithms_and_data_equality(self):
        checks = analysis.read_csv(BASE / "source_hash_audit.csv")
        self.assertEqual(len(checks), 84)
        self.assertTrue(all(r["matches_historical_hash"] == "1" for r in checks))
        packets = {}
        for r in analysis.read_csv(BASE / "input_manifest.csv"):
            packets.setdefault(r["packet_id"], set()).add(r["audit_data_sha256"])
            self.assertEqual((ROOT/r["source_path"]).read_bytes(), (BASE/r["copy_path"]).read_bytes())
        self.assertEqual(len(packets), 17)
        self.assertTrue(all(len(v) == 1 for v in packets.values()))

    def test_final_not_merged_across_batches(self):
        rows = analysis.read_csv(BASE / "labeled_results.csv")
        groups = {}
        for r in rows:
            groups.setdefault(r["cohort"], []).append(r)
        self.assertEqual(len(groups["historical-final"]), 14)
        self.assertEqual(len(groups["wp4-baseline-final"]), 14)
        self.assertEqual(sum(int(r["strict_protocol_pass"]) for r in groups["historical-final"]), 4)
        self.assertEqual(sum(int(r["strict_protocol_pass"]) for r in groups["wp4-baseline-final"]), 5)


class FollowupEvidenceRules(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("followup", BASE / "tools/summarize_poc_followup.py")
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory(prefix="optional1-evidence-test-")
        self.addCleanup(self.temp.cleanup)
        self.temp_path = Path(self.temp.name).resolve()
        self.module.OUT = self.temp_path
        self.module.ROOT = self.temp_path
        self.inventory = [dict(cohort=v, sample_id="S", finding_id="F", code_sha256="testhash")
                          for v in ("v1", "v2", "v3")]
        analysis.write_csv(self.temp_path / "poc_execution.csv", self.inventory)

    def test_partial_execution_never_becomes_final_rate(self):
        r = dict(self.inventory[0], execution_status="not_run", success="")
        f = self.temp_path / "results.csv"
        analysis.write_csv(f, [r])
        self.module.summarize(f)
        rows = analysis.read_csv(self.temp_path / "followup_poc_metrics.csv")
        self.assertTrue(all(r["runnable_rate"] == "" and r["status"] == "partial_not_final" for r in rows))
        self.assertTrue(all(r["possible_success_upper_bound"] == "1.00000000" for r in rows))

    def test_reject_changed_code_and_duplicate_identity(self):
        f = self.temp_path / "results.csv"
        r = dict(self.inventory[0], execution_status="not_run", success="")
        analysis.write_csv(f, [dict(r, code_sha256="changed")])
        with self.assertRaises(ValueError):
            self.module.summarize(f)
        analysis.write_csv(f, [r, r])
        with self.assertRaises(ValueError):
            self.module.summarize(f)

    def test_no_success_without_execution(self):
        f = self.temp_path / "results.csv"
        analysis.write_csv(f, [dict(self.inventory[0], execution_status="not_run", success="true")])
        with self.assertRaises(ValueError):
            self.module.summarize(f)


if __name__ == "__main__":
    unittest.main()
