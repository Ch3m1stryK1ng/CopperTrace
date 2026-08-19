from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_channel_graph_v2 as channel  # noqa: E402


def node(
    value_id: str,
    *,
    object_id: str = "reg:0",
    space: str = "register",
    offset: str = "0x0",
    size: int = 4,
    address: bool = False,
    def_site_id: str = "",
) -> dict:
    return {
        "object_id": object_id,
        "value_id": value_id,
        "space": space,
        "offset": offset,
        "size": size,
        "is_constant": False,
        "is_address": address,
        "is_parameter": False,
        "parameter_slot": None,
        "def_site_id": def_site_id,
    }


def call_return_pointer_facts() -> dict:
    global_pointer = node(
        "value:packetbuf-address",
        object_id="global:20000020:4",
        space="ram",
        offset="0x20000020",
        address=True,
    )
    call_output = node(
        "value:call-result",
        def_site_id="site:caller:call:1",
    )
    return {
        "binary": "/nonexistent/fixture.elf",
        "memory_blocks": [
            {
                "name": ".bss",
                "start": "0x20000000",
                "end": "0x200000ff",
                "read": True,
                "write": True,
                "execute": False,
            }
        ],
        "symbols": [
            {
                "name": "packetbuf_aligned",
                "address": "0x20000020",
                "source": "ELF",
            }
        ],
        "functions": [
            {
                "function_id": "fn:callee",
                "name": "packetbuf_dataptr",
                "pcode_ops": [
                    {
                        "site_id": "site:callee:return:1",
                        "mnemonic": "RETURN",
                        "inputs": [
                            node("value:return-address"),
                            global_pointer,
                        ],
                    }
                ],
            },
            {
                "function_id": "fn:caller",
                "name": "input",
                "pcode_ops": [
                    {
                        "site_id": "site:caller:call:1",
                        "mnemonic": "CALL",
                        "output": call_output,
                        "inputs": [node("value:callee-address")],
                        "call": {"target_function_id": "fn:callee"},
                    }
                ],
            },
        ],
    }


class ChannelGraphAliasTests(unittest.TestCase):
    def test_direct_call_return_pointer_resolves_to_writable_object(self) -> None:
        facts = call_return_pointer_facts()
        resolver = channel.DataObjectResolver(facts)
        call_output = facts["functions"][1]["pcode_ops"][0]["output"]

        resolved = resolver.object_from_node(call_output)

        self.assertIsNotNone(resolved)
        object_id, object_node, provenance = resolved
        self.assertEqual(object_id, "obj:symbol:20000020:packetbuf_aligned")
        self.assertEqual(object_node["name"], "packetbuf_aligned")
        self.assertEqual(provenance, "DIRECT_CALL_RETURN_POINTER")

    def test_value_object_binding_is_alias_fact_not_channel_edge(self) -> None:
        facts = call_return_pointer_facts()
        resolver = channel.DataObjectResolver(facts)

        bindings = channel.build_value_object_bindings(facts, resolver)
        exact_nodes, edges, _ = channel.build_exact_graph(facts, resolver)

        call_binding = next(
            row for row in bindings if row["value_id"] == "value:call-result"
        )
        self.assertEqual(
            call_binding["object_id"],
            "obj:symbol:20000020:packetbuf_aligned",
        )
        self.assertEqual(call_binding["binding_kind"], "POINTER_VALUE_TO_OBJECT_ALIAS")
        self.assertEqual(call_binding["provenance"], "DIRECT_CALL_RETURN_POINTER")
        self.assertEqual(edges, [])
        self.assertEqual(exact_nodes, [])

    def test_source_overlay_materializes_memory_output_only(self) -> None:
        facts = call_return_pointer_facts()
        resolver = channel.DataObjectResolver(facts)
        objects: list[dict] = []
        sources = {
            "source_sites": [
                {
                    "id": "SO1",
                    "function": "input",
                    "site_id": "site:caller:call:1",
                    "decision": "ACCEPT_HEURISTIC",
                    "source_outputs": [
                        {
                            "role": "output_buffer",
                            "kind": "memory_object",
                            "expression": "packetbuf",
                            "object_id": "global:20000020:4",
                            "value_id": "value:packetbuf-address",
                        },
                        {
                            "role": "return_value",
                            "kind": "scalar_value",
                            "expression": "read return",
                            "object_id": "reg:r0",
                            "value_id": "value:read-count",
                        },
                    ],
                }
            ]
        }

        edges = channel.add_source_overlays(objects, sources, facts, resolver)

        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["source_output_role"], "output_buffer")
        self.assertEqual(edges[0]["value_id"], "value:packetbuf-address")
        self.assertNotIn("value:read-count", {edge["value_id"] for edge in edges})

    def test_conflicting_value_object_bindings_are_not_exported(self) -> None:
        class ConflictingResolver:
            ops_by_site: dict = {}

            @staticmethod
            def object_from_node(raw: dict):
                object_id = f"obj:{raw['object_id']}"
                return object_id, {
                    "node_id": object_id,
                    "object_id": object_id,
                    "identity_kind": "TEST",
                }, "TEST"

        first = node("value:ambiguous", object_id="candidate:a", address=True)
        second = node("value:ambiguous", object_id="candidate:b", address=True)
        facts = {
            "functions": [
                {
                    "function_id": "fn:test",
                    "pcode_ops": [
                        {"mnemonic": "COPY", "output": first, "inputs": []},
                        {"mnemonic": "COPY", "output": second, "inputs": []},
                    ],
                }
            ]
        }

        bindings = channel.build_value_object_bindings(facts, ConflictingResolver())

        self.assertEqual(bindings, [])


if __name__ == "__main__":
    unittest.main()
