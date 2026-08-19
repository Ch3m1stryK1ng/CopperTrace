from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "registries" / "software_source_summaries.mango.json"
SCHEMA_PATH = ROOT / "schemas" / "software_source_summary.schema.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


SCHEMA = load_json(SCHEMA_PATH)
REGISTRY = load_json(REGISTRY_PATH)


EXPECTED_INPUT_FUNCTIONS = {
    "read",
    "fread",
    "fgets",
    "recv",
    "recvfrom",
    "custom_param_parser",
    "getenv",
    "GetValue",
    "acosNvramConfig_get",
    "acosNvramConfig_read",
    "nvram_get",
    "nvram_safe_get",
    "bcm_nvram_get",
    "envram_get",
    "wlcsm_nvram_get",
    "dni_nvram_get",
    "PTI_nvram_get",
}


EXPECTED_HANDLERS = {
    "package/argument_resolver/handlers/network.py": {
        "handle_accept",
        "handle_recv",
        "handle_recvfrom",
        "handle_nflog_get_payload",
        "handle_socket",
        "handle_inet_ntoa",
    },
    "package/argument_resolver/handlers/unistd.py": {
        "handle_open",
        "handle_read",
    },
    "package/argument_resolver/handlers/stdio.py": {
        "handle_sprintf",
        "handle_vsprintf",
        "handle_snprintf",
        "handle_vsnprintf",
        "handle_asprintf",
        "handle___sprintf_chk",
        "handle___snprintf_chk",
        "handle_printf",
        "handle_twsystem",
        "handle_exec_cmd",
        "handle_doSystemCmd",
        "handle_dprintf",
        "handle_sscanf",
        "handle_fgets",
        "handle_fopen",
        "handle_fread",
        "handle_popen",
    },
    "package/argument_resolver/handlers/stdlib.py": {
        "handle_malloc",
        "handle_calloc",
        "handle_free",
        "handle_rand",
        "handle_system",
        "handle_getenv",
        "handle_setenv",
        "handle_httpSetEnv",
    },
    "package/argument_resolver/handlers/nvram.py": {
        "handle_nvram_set",
        "handle_SetValue",
        "handle_nvram_safe_set",
        "handle_acosNvramConfig_set",
        "handle_wlcsm_nvram_set",
        "handle_envram_set",
        "handle_bcm_nvram_set",
        "handle_nvram_get",
        "handle_GetValue",
        "handle_nvram_safe_get",
        "handle_acosNvramConfig_get",
        "handle_acosNvramConfig_read",
        "handle_bcm_nvram_get",
        "handle_envram_get",
        "handle_wlcsm_nvram_get",
    },
    "package/argument_resolver/handlers/url_param.py": {
        "handle_custom_param_parser",
    },
}


class MangoSoftwareSourceRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = Draft202012Validator(
            SCHEMA, format_checker=FormatChecker()
        )
        cls.summaries = {row["id"]: row for row in REGISTRY["api_summaries"]}
        cls.summaries_by_name = {
            row["name"]: row for row in REGISTRY["api_summaries"]
        }

    def test_schema_is_valid_and_registry_conforms(self) -> None:
        Draft202012Validator.check_schema(SCHEMA)
        errors = sorted(self.validator.iter_errors(REGISTRY), key=lambda error: list(error.path))
        self.assertEqual([], errors, "\n".join(error.message for error in errors))

    def test_computed_input_function_inventory_is_exact(self) -> None:
        rows = REGISTRY["input_function_inventory"]
        names = [row["name"] for row in rows]

        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), EXPECTED_INPUT_FUNCTIONS)
        self.assertEqual(
            {row["name"] for row in rows if row["origin"] == "direct_literal"},
            {"read", "fread", "fgets", "recv", "recvfrom", "custom_param_parser"},
        )

    def test_declared_inputs_without_handlers_remain_inventory_only(self) -> None:
        missing = {
            row["name"]
            for row in REGISTRY["input_function_inventory"]
            if row["handler_status"] == "declared_without_handler"
        }

        self.assertEqual(missing, {"dni_nvram_get", "PTI_nvram_get"})
        self.assertTrue(missing.isdisjoint(self.summaries_by_name))

    def test_all_modeled_inputs_link_to_their_exact_summary(self) -> None:
        for row in REGISTRY["input_function_inventory"]:
            if row["handler_status"] != "modeled":
                continue
            with self.subTest(name=row["name"]):
                summary = self.summaries[row["summary_id"]]
                self.assertEqual(summary["name"], row["name"])
                self.assertEqual(
                    summary["compatibility_specific"],
                    row["compatibility_specific"],
                )
                self.assertEqual(summary["core_eligible"], row["core_eligible"])

    def test_source_producing_nflog_handler_is_not_rewritten_as_declared_input(self) -> None:
        input_names = {row["name"] for row in REGISTRY["input_function_inventory"]}

        self.assertIn("nflog_get_payload", self.summaries_by_name)
        self.assertEqual(
            self.summaries_by_name["nflog_get_payload"]["summary_kind"], "source"
        )
        self.assertNotIn("nflog_get_payload", input_names)

    def test_handler_inventory_covers_all_six_modules(self) -> None:
        actual: dict[str, set[str]] = {}
        pairs: list[tuple[str, str]] = []
        for row in REGISTRY["handler_inventory"]:
            actual.setdefault(row["module"], set()).add(row["handler"])
            pairs.append((row["module"], row["handler"]))

        self.assertEqual(len(pairs), 49)
        self.assertEqual(len(pairs), len(set(pairs)))
        self.assertEqual(actual, EXPECTED_HANDLERS)

    def test_source_and_handle_handlers_link_to_matching_summaries(self) -> None:
        linked = {
            row["summary_id"]
            for row in REGISTRY["handler_inventory"]
            if row["source_disposition"] in {"source", "handle_producer"}
        }

        self.assertEqual(linked, set(self.summaries))
        for row in REGISTRY["handler_inventory"]:
            summary_id = row.get("summary_id")
            if summary_id is None:
                continue
            with self.subTest(handler=row["handler"]):
                summary = self.summaries[summary_id]
                self.assertEqual(summary["handler"]["module"], row["module"])
                self.assertEqual(summary["handler"]["method"], row["handler"])

    def test_argument_and_output_references_are_well_formed(self) -> None:
        for summary in REGISTRY["api_summaries"]:
            with self.subTest(name=summary["name"]):
                indices = [argument["index"] for argument in summary["arguments"]]
                self.assertEqual(len(indices), len(set(indices)))
                index_set = set(indices)

                for output in summary["outputs"]:
                    if output["carrier"] == "argument_pointee":
                        self.assertIn(output["argument_index"], index_set)

                provenance = summary.get("handle_provenance")
                if provenance is not None:
                    for key in ("consumes_argument", "parent_argument"):
                        if key in provenance:
                            self.assertIn(provenance[key], index_set)

                if summary["summary_kind"] == "source":
                    self.assertTrue(
                        any(output["external_data"] for output in summary["outputs"])
                    )

    def test_compatibility_specific_entries_cannot_enter_generalized_core(self) -> None:
        for collection in ("input_function_inventory", "api_summaries"):
            for row in REGISTRY[collection]:
                if row["compatibility_specific"]:
                    with self.subTest(collection=collection, name=row["name"]):
                        self.assertFalse(row["core_eligible"])

        mutated = copy.deepcopy(REGISTRY)
        exact = next(
            row for row in mutated["api_summaries"] if row["name"] == "nvram_get"
        )
        exact["core_eligible"] = True
        self.assertTrue(list(self.validator.iter_errors(mutated)))

    def test_generalized_standard_sources_are_separate_from_exact_compatibility_names(self) -> None:
        generalized = {"read", "fread", "fgets", "recv", "recvfrom", "getenv"}
        exact = {
            "custom_param_parser",
            "nflog_get_payload",
            "GetValue",
            "acosNvramConfig_get",
            "acosNvramConfig_read",
            "nvram_get",
            "nvram_safe_get",
            "bcm_nvram_get",
            "envram_get",
            "wlcsm_nvram_get",
        }

        for name in generalized:
            self.assertFalse(self.summaries_by_name[name]["compatibility_specific"])
            self.assertTrue(self.summaries_by_name[name]["core_eligible"])
        for name in exact:
            self.assertTrue(self.summaries_by_name[name]["compatibility_specific"])
            self.assertFalse(self.summaries_by_name[name]["core_eligible"])

    def test_mango_calling_convention_quirks_are_preserved(self) -> None:
        open_summary = self.summaries_by_name["open"]
        self.assertEqual(open_summary["calling_convention"]["lookup_name"], "fread")
        self.assertEqual(
            open_summary["calling_convention"]["maximum_consumed_argument_count"], 2
        )

        recvfrom = self.summaries_by_name["recvfrom"]
        self.assertEqual(recvfrom["calling_convention"]["declared_argument_count"], 6)
        self.assertEqual(
            [arg["index"] for arg in recvfrom["arguments"] if arg["consumed_by_handler"]],
            [0, 1, 2],
        )

        acos_read = self.summaries_by_name["acosNvramConfig_read"]
        self.assertEqual(
            acos_read["calling_convention"]["declared_argument_count"], 1
        )
        self.assertEqual(
            acos_read["calling_convention"]["maximum_consumed_argument_count"], 2
        )

        parser = self.summaries_by_name["custom_param_parser"]
        self.assertEqual(
            parser["calling_convention"]["lookup_name"], "query_param_parser"
        )
        self.assertEqual(len(parser["calling_convention"]["variants"]), 2)

    def test_buffer_and_return_models_match_mango(self) -> None:
        read = self.summaries_by_name["read"]
        self.assertEqual(read["size"]["cap_bytes"], 32)
        self.assertIn("original arg[2]", read["outputs"][1]["semantics"])

        fread = self.summaries_by_name["fread"]
        self.assertEqual(fread["size"]["cap_bytes"], 4096)
        self.assertIn("TOP", fread["outputs"][1]["semantics"])

        fgets = self.summaries_by_name["fgets"]
        self.assertEqual(fgets["outputs"][1]["role"], "return_pointer")
        self.assertEqual(fgets["outputs"][1]["carrier"], "return")

        getvalue = self.summaries_by_name["GetValue"]
        self.assertEqual(getvalue["outputs"][0]["argument_index"], 1)
        self.assertEqual(getvalue["outputs"][1]["carrier"], "none")

    def test_handle_provenance_includes_standard_descriptors_and_parent_links(self) -> None:
        initial = {row["value"]: row for row in REGISTRY["initial_handles"]}
        self.assertEqual(set(initial), {0, 1, 2})
        self.assertTrue(initial[0]["ingress_capable"])
        self.assertFalse(initial[1]["ingress_capable"])
        self.assertFalse(initial[2]["ingress_capable"])

        accept = self.summaries_by_name["accept"]["handle_provenance"]
        self.assertEqual(accept["consumes_argument"], 0)
        self.assertEqual(accept["parent_argument"], 0)
        self.assertTrue(accept["produces_return_handle"])

        read = self.summaries_by_name["read"]["handle_provenance"]
        self.assertEqual(read["consumes_argument"], 0)
        self.assertFalse(read["produces_return_handle"])

    def test_provenance_is_revision_pinned_and_references_inventoried_files(self) -> None:
        upstream = REGISTRY["upstream"]
        self.assertEqual(
            upstream["revision"], "a26bf93fec67929a9e13d9a1abfde8811e5f2f97"
        )
        files = {row["path"] for row in upstream["files"]}

        references = list(REGISTRY["source_defaults"]["provenance"])
        references.extend(row["provenance"] for row in REGISTRY["initial_handles"])
        for row in REGISTRY["input_function_inventory"]:
            references.extend(row["provenance"])
        for row in REGISTRY["api_summaries"]:
            references.extend(row["provenance"])

        for reference in references:
            with self.subTest(symbol=reference["symbol"]):
                self.assertIn(reference["path"], files)
                self.assertGreater(reference["line"], 0)


if __name__ == "__main__":
    unittest.main()
