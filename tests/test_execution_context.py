import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "build_execution_context", SCRIPTS / "build_execution_context.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ExecutionContextTests(unittest.TestCase):
    def test_extracts_function_ids_from_alert_paths_in_order(self):
        alert = {
            "sink_site_id": "site:00403000:00403010:1",
            "parameter_results": [
                {
                    "paths": [
                        {
                            "path": [
                                {"site_id": "site:00402000:00402010:2"},
                                {"site_id": "site:00401000:00401010:3"},
                                {"site_id": "site:00402000:00402020:4"},
                            ]
                        }
                    ]
                }
            ],
        }
        self.assertEqual(
            MODULE.site_function_ids(alert),
            ["fn:00403000", "fn:00402000", "fn:00401000"],
        )

    def test_load_functions_preserves_decompiled_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "functions.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "function_id": "fn:00401000",
                        "name": "consumer",
                        "body": "void consumer(void) {}",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            rows = MODULE.load_functions(path)
        self.assertEqual(rows["fn:00401000"]["name"], "consumer")
        self.assertIn("consumer", rows["fn:00401000"]["body"])


if __name__ == "__main__":
    unittest.main()
