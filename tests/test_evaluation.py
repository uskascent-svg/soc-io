import json
import unittest
from pathlib import Path

from socio.evaluation import evaluate


class EvaluationBaselineTests(unittest.TestCase):
    def test_synthetic_baseline_is_reproducible(self):
        path = Path("examples/evaluation_baseline.json")
        dataset = json.loads(path.read_text(encoding="utf-8"))
        result = evaluate(dataset)
        self.assertEqual(result["case_count"], 5)
        self.assertEqual(result["confusion_counts_rule_case"]["tp"], 3)
        self.assertEqual(result["confusion_counts_rule_case"]["fp"], 0)
        self.assertEqual(result["confusion_counts_rule_case"]["fn"], 0)
        self.assertEqual(result["metrics"]["precision"], 1.0)
        self.assertIn("not estimates", " ".join(result["limitations"]))


if __name__ == "__main__":
    unittest.main()
