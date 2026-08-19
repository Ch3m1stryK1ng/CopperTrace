from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_channel_graph_v2 as channel  # noqa: E402
import dataflow_objects  # noqa: E402
import run_sink_backward_dfa as dfa  # noqa: E402


def node(
    value_id: str,
    object_id: str,
    *,
    data_type: str = "void *",
    def_site_id: str = "",
    parameter_slot: int | None = None,
) -> dict:
    return {
        "value_id": value_id,
        "object_id": object_id,
        "space": "register",
        "offset": "0x20",
        "size": 4,
        "high_name": "",
        "high_data_type": data_type,
        "is_parameter": parameter_slot is not None,
        "parameter_slot": parameter_slot,
        "is_constant": False,
        "is_address": False,
        "def_site_id": def_site_id,
    }


def const(value: int) -> dict:
    return {
        "value_id": f"const:{value:x}:4",
        "object_id": f"const:{value:x}:4",
        "space": "const",
        "offset": hex(value),
        "size": 4,
        "is_constant": True,
        "is_address": False,
        "def_site_id": "",
    }


class RuntimeDataflowObjectTests(unittest.TestCase):
    def test_pointer_call_result_and_field_load_keep_context_root(self) -> None:
        packet = node("value:packet", "reg:packet", data_type="struct packet *", def_site_id="site:alloc")
        field_address = node("value:field-address", "unique:field", def_site_id="site:field")
        field_pointer = node("value:field-pointer", "reg:field", data_type="uint8_t *", def_site_id="site:load")
        facts = {
            "binary": "",
            "memory_blocks": [],
            "symbols": [],
            "functions": [
                {
                    "function_id": "fn:producer",
                    "name": "f_100",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:alloc",
                            "mnemonic": "CALL",
                            "output": packet,
                            "inputs": [const(0x2000)],
                            "call": {"target_function_id": "fn:factory"},
                        },
                        {
                            "site_id": "site:field",
                            "mnemonic": "PTRSUB",
                            "output": field_address,
                            "inputs": [packet, const(0x10)],
                        },
                        {
                            "site_id": "site:load",
                            "mnemonic": "LOAD",
                            "output": field_pointer,
                            "inputs": [const(0), field_address],
                        },
                    ],
                },
                {"function_id": "fn:factory", "name": "f_200", "parameters": [], "pcode_ops": []},
            ],
        }
        resolver = channel.DataObjectResolver(facts)
        runtime = dataflow_objects.RuntimeObjectIndex(
            facts,
            static_object=resolver.object_from_node,
            stack_descriptor=resolver.stack_descriptor,
            stack_object_id=channel._stack_local_object_id,
        )
        packet_binding = runtime.resolve(packet, "fn:producer")
        field_binding = runtime.resolve(field_pointer, "fn:producer")
        self.assertEqual(packet_binding["object_id"], "obj:call-result:site:alloc")
        self.assertEqual(field_binding["root_object_id"], packet_binding["object_id"])
        self.assertIn("deref", field_binding["access_path"])

    def test_unique_static_pointer_slot_store_load_preserves_object_identity(self) -> None:
        allocated = node(
            "value:allocated",
            "reg:allocated",
            data_type="uint8_t *",
            def_site_id="site:alloc",
        )
        slot = {
            **node("value:slot", "global:slot", data_type="uint8_t **"),
            "space": "ram",
            "offset": "0x20001000",
            "is_address": True,
        }
        loaded = node(
            "value:loaded",
            "reg:loaded",
            data_type="uint8_t *",
            def_site_id="site:load",
        )
        facts = {
            "functions": [
                {
                    "function_id": "fn:flow",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:alloc",
                            "mnemonic": "CALL",
                            "output": allocated,
                            "inputs": [const(0x1000)],
                            "call": {"target_function_id": "fn:factory"},
                        },
                        {
                            "site_id": "site:store",
                            "mnemonic": "STORE",
                            "output": None,
                            "inputs": [const(0), slot, allocated],
                        },
                        {
                            "site_id": "site:load",
                            "mnemonic": "LOAD",
                            "output": loaded,
                            "inputs": [const(0), slot],
                        },
                    ],
                },
                {
                    "function_id": "fn:factory",
                    "parameters": [],
                    "pcode_ops": [],
                },
            ]
        }

        def static_object(raw: dict):
            if raw.get("is_address") and raw.get("offset") == "0x20001000":
                return (
                    "obj:static:pointer-slot",
                    {
                        "storage_kind": "STATIC_WRITABLE_DATA",
                        "identity_kind": "STATIC_OBJECT",
                    },
                    "TEST_STATIC_ADDRESS",
                )
            return None

        runtime = dataflow_objects.RuntimeObjectIndex(
            facts,
            static_object=static_object,
            stack_descriptor=lambda raw, function_id: None,
            stack_object_id=lambda function_id, offset: "",
        )
        allocated_binding = runtime.resolve(allocated, "fn:flow")
        loaded_binding = runtime.resolve(loaded, "fn:flow")
        self.assertEqual(loaded_binding["object_id"], allocated_binding["object_id"])
        self.assertEqual(
            loaded_binding["provenance"],
            "HIGH_PCODE_UNIQUE_POINTER_SLOT_STORE_LOAD",
        )
        self.assertEqual(loaded_binding["precision"], "MAY")

    def test_primitive_effect_can_be_selected_by_destination_object(self) -> None:
        packet = node("value:packet", "reg:packet", data_type="struct packet *")
        facts = {"functions": []}
        graph = {
            "nodes": [],
            "edges": [],
            "value_object_bindings": [
                {"value_id": "value:packet", "object_id": "obj:packet"},
            ],
            "primitive_memory_effects": [
                {
                    "effect_id": "effect:copy",
                    "effect_kind": "PRIMITIVE_MEMORY_COPY",
                    "function_id": "fn:producer",
                    "site_id": "site:copy",
                    "source": {"atom_id": "value:source", "object_id": "obj:input"},
                    "destination": {
                        "atom_id": "value:field",
                        "object_id": "obj:packet-field",
                        "base_object_id": "obj:packet",
                        "access_path": ["byte_offset:16", "deref"],
                    },
                }
            ],
        }
        sources = {
            "source_sites": [
                {
                    "id": "SO1",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "source_outputs": [
                        {"kind": "scalar_value", "value_id": "value:source", "object_id": "obj:input"}
                    ],
                }
            ]
        }
        index = dfa.ProgramIndex(facts, graph, strict=True)
        result = dfa.trace_parameter(
            {"role": "src", **packet},
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=16,
        )
        self.assertEqual(result["status"], "SOURCE_REACHED_DETERMINISTIC")
        step = result["paths"][0]["path"][0]
        self.assertEqual(step["kind"], "PRIMITIVE_MEMORY_EFFECT")
        self.assertEqual(step["consumer_binding"]["atom_id"], "value:packet")
        self.assertEqual(step["predecessor_binding"]["atom_id"], "value:source")


if __name__ == "__main__":
    unittest.main()
