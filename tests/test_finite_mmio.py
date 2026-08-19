from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_source_artifacts as miner  # noqa: E402
import device_dispatch_resolver  # noqa: E402
import finite_initialized_table  # noqa: E402


REGISTRY = json.loads((ROOT / "registries" / "source_patterns.v0.json").read_text())


def node(
    value_id: str,
    *,
    offset: int = 0,
    constant: bool = False,
    address: bool = False,
    parameter_slot: int | None = None,
    name: str = "",
    size: int = 4,
) -> dict:
    return {
        "value_id": value_id,
        "object_id": value_id,
        "offset": hex(offset),
        "size": size,
        "space": "ram" if address else "unique",
        "is_constant": constant,
        "is_address": address,
        "is_parameter": parameter_slot is not None,
        "parameter_slot": parameter_slot,
        "high_name": name,
    }


def finite_mmio_function() -> dict:
    table = node("table", offset=0x1000, address=True)
    selector = node("selector", parameter_slot=0, name="selector")
    stride = node("stride", offset=4, constant=True)
    slot = node("slot")
    base = node("base")
    offset = node("register-offset", offset=8, constant=True)
    register = node("register")
    data = node("data", name="incoming", size=1)
    destination = node("destination", parameter_slot=1, name="output")
    return {
        "name": "arbitrary_transport_body",
        "function_id": "fn:00001000",
        "entry": "0x1000",
        "parameters": [
            {"index": 0, "name": "selector", "data_type": "unsigned int"},
            {"index": 1, "name": "output", "data_type": "unsigned char *"},
        ],
        "decompiled_c": "void arbitrary_transport_body(unsigned selector, unsigned char *output) { *output = *(volatile unsigned char *)computed; }",
        "pcode_ops": [
            {
                "site_id": "site:1000:1004:1",
                "mnemonic": "PTRADD",
                "output": slot,
                "inputs": [table, selector, stride],
            },
            {
                "site_id": "site:1000:1008:1",
                "mnemonic": "LOAD",
                "output": base,
                "inputs": [node("space-1", offset=1, constant=True), slot],
            },
            {
                "site_id": "site:1000:100c:1",
                "mnemonic": "INT_ADD",
                "output": register,
                "inputs": [base, offset],
            },
            {
                "site_id": "site:1000:1010:1",
                "mnemonic": "LOAD",
                "output": data,
                "inputs": [node("space-2", offset=1, constant=True), register],
            },
            {
                "site_id": "site:1000:1014:1",
                "mnemonic": "STORE",
                "output": None,
                "inputs": [node("space-3", offset=1, constant=True), destination, data],
            },
        ],
    }


def initialized_table_memory(*, writable: bool = False) -> device_dispatch_resolver.InitializedMemory:
    data = (0x40001000).to_bytes(4, "little") + (0x40002000).to_bytes(4, "little")
    return device_dispatch_resolver.InitializedMemory.from_regions(
        [
            device_dispatch_resolver.MemoryRegion(
                0x1000,
                data,
                source="elf:PT_LOAD[0]",
                writable=writable,
                name="initialized-object-bytes",
            )
        ],
        symbols=[
            device_dispatch_resolver.MemorySymbol(
                address=0x1000,
                size=len(data),
                kind="STT_OBJECT",
                source="elf:.symtab",
                section=".rodata",
                writable=writable,
            )
        ],
        pointer_size=4,
    )


def finite_struct_table_function() -> dict:
    selector = node("struct-selector", parameter_slot=0, name="selector")
    scale = node("struct-stride", offset=0x18, constant=True)
    scaled = node("scaled-selector")
    literal = node("table-literal", offset=0x1400, address=True)
    slot = node("struct-slot")
    base = node("struct-base")
    register = node("struct-register")
    data = node("struct-data", size=1)
    return {
        "name": "generic_struct_table_transport",
        "function_id": "fn:00002000",
        "parameters": [{"index": 0, "name": "selector", "data_type": "unsigned"}],
        "pcode_ops": [
            {
                "site_id": "site:2000:2004:1",
                "mnemonic": "INT_MULT",
                "output": scaled,
                "inputs": [selector, scale],
            },
            {
                "site_id": "site:2000:2008:1",
                "mnemonic": "INT_ADD",
                "output": slot,
                "inputs": [scaled, literal],
            },
            {
                "site_id": "site:2000:200c:1",
                "mnemonic": "LOAD",
                "output": base,
                "inputs": [node("space-struct-1", offset=1, constant=True), slot],
            },
            {
                "site_id": "site:2000:2010:1",
                "mnemonic": "INT_ADD",
                "output": register,
                "inputs": [base, node("data-offset", offset=0x28, constant=True)],
            },
            {
                "site_id": "site:2000:2014:1",
                "mnemonic": "LOAD",
                "output": data,
                "inputs": [node("space-struct-2", offset=1, constant=True), register],
            },
        ],
    }


def initialized_struct_table_memory() -> device_dispatch_resolver.InitializedMemory:
    table = bytearray(0x30)
    table[0:4] = (0x42001800).to_bytes(4, "little")
    table[0x18:0x1C] = (0x42001C00).to_bytes(4, "little")
    return device_dispatch_resolver.InitializedMemory.from_regions(
        [
            device_dispatch_resolver.MemoryRegion(
                0x1400,
                (0x1800).to_bytes(4, "little"),
                source="elf:literal-pool",
                writable=False,
            ),
            device_dispatch_resolver.MemoryRegion(
                0x1800,
                bytes(table),
                source="elf:rodata",
                writable=False,
            ),
        ],
        symbols=[
            device_dispatch_resolver.MemorySymbol(
                address=0x1800,
                size=len(table),
                kind="STT_OBJECT",
                source="elf:.symtab",
                section=".rodata",
                writable=False,
            )
        ],
        pointer_size=4,
    )


def register_profile(*, second_role: str = "RX_DATA") -> dict:
    return {
        "schema_version": "ct-mini-hardware-metadata-v2",
        "metadata_source": "vendor_register_manual",
        "registers": [
            {
                "address": "0x40001008",
                "role": "RX_DATA",
                "evidence_reference": "register map A",
            },
            {
                "address": "0x40002008",
                "role": second_role,
                "evidence_reference": "register map B",
            },
        ],
    }


class FiniteInitializedTableTests(unittest.TestCase):
    def test_struct_table_stride_and_initialized_base_literal_are_enumerated(self) -> None:
        function = finite_struct_table_function()
        _, definitions = miner.pcode_indexes(function)
        result = finite_initialized_table.enumerate_computed_mmio_load(
            function["pcode_ops"][-1],
            definitions,
            initialized_struct_table_memory(),
        )

        self.assertEqual(result["status"], "enumerated")
        self.assertEqual(result["address_candidates"], [0x42001828, 0x42001C28])
        self.assertEqual(result["table_stride"], 0x18)
        self.assertEqual(result["selector_domain"]["entry_count"], 2)
        self.assertEqual(
            result["proof_kind"],
            "finite_initialized_struct_table_computed_mmio",
        )
        self.assertEqual(
            result["table_base_evidence"]["kind"],
            "initialized_pointer_literal",
        )

    def test_restricted_shape_enumerates_immutable_object_extent(self) -> None:
        function = finite_mmio_function()
        _, definitions = miner.pcode_indexes(function)
        result = finite_initialized_table.enumerate_computed_mmio_load(
            function["pcode_ops"][3],
            definitions,
            initialized_table_memory(),
        )

        self.assertEqual(result["status"], "enumerated")
        self.assertEqual(result["address_candidates"], [0x40001008, 0x40002008])
        self.assertEqual(result["selector_domain"]["entry_count"], 2)
        self.assertEqual(result["proof_kind"], "finite_initialized_table_computed_mmio")

    def test_writable_table_is_unresolved_and_never_enumerated(self) -> None:
        function = finite_mmio_function()
        _, definitions = miner.pcode_indexes(function)
        result = finite_initialized_table.enumerate_computed_mmio_load(
            function["pcode_ops"][3],
            definitions,
            initialized_table_memory(writable=True),
        )

        self.assertEqual(result["status"], "unresolved")
        self.assertEqual(result["reason"], "table_object_is_writable")
        self.assertEqual(result["address_candidates"], [])

    def test_missing_exact_object_extent_is_unresolved(self) -> None:
        function = finite_mmio_function()
        _, definitions = miner.pcode_indexes(function)
        memory = device_dispatch_resolver.InitializedMemory.from_regions(
            [
                device_dispatch_resolver.MemoryRegion(
                    0x1000,
                    (0x40001000).to_bytes(4, "little"),
                    writable=False,
                )
            ],
            pointer_size=4,
        )
        result = finite_initialized_table.enumerate_computed_mmio_load(
            function["pcode_ops"][3], definitions, memory
        )

        self.assertEqual(result["status"], "unresolved")
        self.assertEqual(result["reason"], "immutable_table_extent_not_unique")

    def test_legacy_single_query_and_plural_query_remain_compatible(self) -> None:
        direct_load = {
            "site_id": "site:2000:2004:1",
            "mnemonic": "LOAD",
            "output": node("direct-data", size=1),
            "inputs": [
                node("direct-space", offset=1, constant=True),
                node("direct-address", offset=0x40003008, constant=True),
            ],
        }
        singular = miner.mmio_load_register_query(direct_load, {}, {})
        plural = miner.mmio_load_register_queries(direct_load, {}, {})

        self.assertEqual(singular, {"absolute_address": 0x40003008})
        self.assertEqual(plural, [singular])

    def test_all_metadata_proved_data_addresses_confirm_one_source(self) -> None:
        function = finite_mmio_function()
        facts = {"hardware_profile": register_profile(), "functions": [function]}
        confirmed, candidates, raw, _, _ = miner.structured_mmio_and_dma_scan(
            facts,
            REGISTRY,
            start_source_index=1,
            start_candidate_index=1,
            initialized_memory=initialized_table_memory(),
        )

        self.assertEqual(len(confirmed), 1)
        self.assertEqual(candidates, [])
        self.assertEqual(raw, [])
        proof = confirmed[0]["proof"]
        self.assertEqual(proof["address_recovery"], "finite_initialized_table")
        self.assertEqual(proof["register_addresses"], ["0x40001008", "0x40002008"])
        self.assertTrue(proof["register_resolution"]["all_candidates_external_input"])

    def test_observed_accesses_export_every_finite_address_candidate(self) -> None:
        function = finite_mmio_function()
        rows = miner.observed_mmio_accesses(
            {"functions": [function]},
            initialized_memory=initialized_table_memory(),
        )

        self.assertEqual(
            [row["address"] for row in rows],
            ["0x40001008", "0x40002008"],
        )
        self.assertTrue(
            all(row["address_recovery"] == "finite_initialized_table" for row in rows)
        )

    def test_structural_receive_flow_without_metadata_is_heuristic(self) -> None:
        function = finite_mmio_function()
        facts = {"functions": [function]}
        confirmed, candidates, raw, _, _ = miner.structured_mmio_and_dma_scan(
            facts,
            REGISTRY,
            start_source_index=1,
            start_candidate_index=1,
            initialized_memory=initialized_table_memory(),
        )

        self.assertEqual(confirmed, [])
        self.assertEqual(raw, [])
        self.assertEqual(len(candidates), 1)
        admitted = miner.heuristic_source_row(candidates[0], "SO0001")
        self.assertIsNotNone(admitted)
        self.assertEqual(admitted["decision"], "ACCEPT_HEURISTIC")
        self.assertEqual(
            candidates[0]["static_bindings"]["address_recovery"],
            "finite_initialized_table",
        )

    def test_unenumerable_table_is_only_an_unresolved_observation(self) -> None:
        function = finite_mmio_function()
        facts = {"functions": [function]}
        memory = initialized_table_memory(writable=True)
        confirmed, candidates, raw, _, _ = miner.structured_mmio_and_dma_scan(
            facts,
            REGISTRY,
            start_source_index=1,
            start_candidate_index=1,
            initialized_memory=memory,
        )

        self.assertEqual(confirmed, [])
        self.assertEqual(candidates, [])
        self.assertEqual(len(raw), 1)
        self.assertEqual(raw[0]["observation"], "COMPUTED_MMIO_READ")
        self.assertEqual(raw[0]["reason"], "table_object_is_writable")


class SourceFunctionBindingContractTests(unittest.TestCase):
    @staticmethod
    def source(site_id: str) -> dict:
        return {
            "id": "SO0001",
            "site_id": site_id,
            "function_id": "",
            "source_outputs": [
                {"kind": "scalar_value", "value_id": "value:source", "object_id": ""}
            ],
            "decision": "ACCEPT_DETERMINISTIC",
        }

    def test_unique_site_owner_supplies_function_id(self) -> None:
        row = self.source("site:1000:1010:1")
        facts = {
            "functions": [
                {
                    "function_id": "fn:00001000",
                    "pcode_ops": [{"site_id": "site:1000:1010:1"}],
                }
            ]
        }

        blockers = miner.bind_source_rows_to_program_functions([row], facts)

        self.assertEqual(blockers, [])
        self.assertEqual(row["function_id"], "fn:00001000")
        self.assertEqual(
            row["function_id_binding"]["kind"],
            "unique_program_facts_site_owner",
        )
        definitions = miner.software_source_engine.source_definitions([row])
        self.assertEqual(definitions[0]["function_id"], "fn:00001000")

    def test_missing_site_owner_stays_empty_and_emits_blocker(self) -> None:
        row = self.source("site:1000:1010:1")
        blockers = miner.bind_source_rows_to_program_functions([row], {"functions": []})

        self.assertEqual(row["function_id"], "")
        self.assertEqual(blockers[0]["reason"], "source_site_function_mapping_not_found")

    def test_ambiguous_site_owner_is_not_guessed_from_function_name(self) -> None:
        row = self.source("site:shared")
        row["function"] = "looks_like_one_owner"
        facts = {
            "functions": [
                {"function_id": "fn:1", "name": "looks_like_one_owner", "pcode_ops": [{"site_id": "site:shared"}]},
                {"function_id": "fn:2", "name": "other", "pcode_ops": [{"site_id": "site:shared"}]},
            ]
        }

        blockers = miner.bind_source_rows_to_program_functions([row], facts)

        self.assertEqual(row["function_id"], "")
        self.assertEqual(blockers[0]["reason"], "source_site_function_mapping_not_unique")
        self.assertEqual(blockers[0]["candidate_function_ids"], ["fn:1", "fn:2"])


if __name__ == "__main__":
    unittest.main()
