import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "review_evidence_store", SCRIPTS / "review_evidence_store.py"
)
STORE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = STORE
SPEC.loader.exec_module(STORE)


def facts():
    return {
        "static_objects": [
            {"object_id": "stack:1", "kind": "STACK_ARRAY", "extent": 32}
        ],
        "functions": [
            {
                "function_id": "fn:1000",
                "name": "copy_packet",
                "decompiled_c": "void copy_packet(void) { memcpy(dst, src, len); }",
                "pcode_ops": [
                    {
                        "site_id": "site:1000:1004:1",
                        "block_id": "b0",
                        "mnemonic": "COPY",
                        "output": {"value_id": "value:out"},
                        "inputs": [{"value_id": "value:in"}],
                    },
                    {
                        "site_id": "site:1000:1008:2",
                        "block_id": "b0",
                        "mnemonic": "CBRANCH",
                        "inputs": [{"value_id": "value:cond"}],
                    },
                ],
                "basic_blocks": [
                    {
                        "block_id": "b0",
                        "predecessor_block_ids": [],
                        "successor_block_ids": ["b1", "b2"],
                    },
                    {
                        "block_id": "b1",
                        "predecessor_block_ids": ["b0"],
                        "successor_block_ids": [],
                    },
                    {
                        "block_id": "b2",
                        "predecessor_block_ids": ["b0"],
                        "successor_block_ids": [],
                    },
                ],
            }
        ],
    }


class ReviewEvidenceStoreTests(unittest.TestCase):
    def test_prepares_neutral_decompiled_file_and_rejects_cve_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.c"
            destination = root / "FW0001" / "decompiled.c"
            source.write_text("void f(void) {}\n", encoding="utf-8")
            result = STORE.prepare_sanitized_decompiled_c(source, destination)
            self.assertTrue(destination.is_file())
            self.assertEqual(result["line_count"], 1)

            source.write_text("/* CVE-2020-10065 */\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                STORE.prepare_sanitized_decompiled_c(source, destination)

    def test_tools_are_read_only_bounded_and_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            code = Path(directory) / "decompiled.c"
            code.write_text("\n".join(f"line {index}" for index in range(300)), encoding="utf-8")
            store = STORE.ReviewEvidenceStore(
                neutral_firmware_id="FW0001",
                decompiled_c_path=code,
                program_facts=facts(),
            )

            function = store.get_function({"function_id": "fn:1000"})
            excerpt = store.get_code_range({"start_line": 1, "end_line": 999})
            pcode = store.get_pcode_slice(
                {"function_id": "fn:1000", "value_ids": ["value:in"], "max_ops": 64}
            )
            obj = store.get_object_fact({"object_id": "stack:1"})

            self.assertIn("memcpy", function["result"]["decompiled_c"])
            self.assertEqual(excerpt["result"]["end_line"], 200)
            self.assertEqual(len(pcode["result"]["ops"]), 1)
            self.assertEqual(obj["result"]["facts"][0]["extent"], 32)
            self.assertEqual(len(store.query_log), 4)
            self.assertGreaterEqual(len(store.evidence_reference_ids()), 4)
            self.assertIn("site:1000:1004:1", store.evidence_reference_ids())
            self.assertIn("value:in", store.evidence_reference_ids())

    def test_no_filesystem_or_search_tool_is_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            code = Path(directory) / "decompiled.c"
            code.write_text("void f(void) {}\n", encoding="utf-8")
            store = STORE.ReviewEvidenceStore(
                neutral_firmware_id="FW0001",
                decompiled_c_path=code,
                program_facts=facts(),
            )
            names = {tool.name for tool in store.tools()}
            self.assertEqual(
                names,
                {
                    "get_function",
                    "get_pcode_slice",
                    "get_cfg_relation",
                    "get_object_fact",
                },
            )

    def test_batch_scope_rejects_cross_alert_function_query(self):
        with tempfile.TemporaryDirectory() as directory:
            code = Path(directory) / "decompiled.c"
            code.write_text("void f(void) {}\n", encoding="utf-8")
            base = STORE.ReviewEvidenceStore(
                neutral_firmware_id="FW0001",
                decompiled_c_path=code,
                program_facts=facts(),
            )
            store = base.fork(
                allowed_references_by_alert={
                    "A1": {"fn:1000"},
                    "A2": {"fn:other"},
                }
            )

            store.get_function({"alert_id": "A1", "function_id": "fn:1000"})
            with self.assertRaises(ValueError):
                store.get_function({"alert_id": "A2", "function_id": "fn:1000"})

    def test_initial_context_preloads_sink_function_without_tool_query(self):
        with tempfile.TemporaryDirectory() as directory:
            code = Path(directory) / "decompiled.c"
            code.write_text("void f(void) {}\n", encoding="utf-8")
            store = STORE.ReviewEvidenceStore(
                neutral_firmware_id="FW0001",
                decompiled_c_path=code,
                program_facts=facts(),
            )
            context = store.initial_decompiled_context(
                {
                    "alert": {"sink_boundary_site_id": "site:1000:1004:1"},
                    "check_evidence": {"represented_alerts": []},
                }
            )
            self.assertEqual(context["function_count"], 1)
            self.assertEqual(context["functions"][0]["function_id"], "fn:1000")
            self.assertIn("memcpy", context["functions"][0]["decompiled_c"])
            self.assertEqual(store.query_log, [])


if __name__ == "__main__":
    unittest.main()
