from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_channel_graph_v2 as channel  # noqa: E402


def node(
    object_id: str,
    value_id: str,
    *,
    space: str = "register",
    offset: str = "0x0",
    size: int = 4,
    constant: bool = False,
    address: bool = False,
    def_site_id: str = "",
) -> dict:
    return {
        "object_id": object_id,
        "value_id": value_id,
        "space": space,
        "offset": offset,
        "size": size,
        "is_constant": constant,
        "is_address": address,
        "is_parameter": False,
        "parameter_slot": None,
        "def_site_id": def_site_id,
    }


def memory_facts(*, read_offset: int = 6, reader_name: str = "main") -> dict:
    shared_write = node(
        "global:20000004:4",
        "value:shared-write-address",
        space="ram",
        offset="0x20000004",
        address=True,
    )
    shared_read = node(
        f"global:{0x20000000 + read_offset:08x}:2",
        "value:shared-read-address",
        space="ram",
        offset=f"0x{0x20000000 + read_offset:x}",
        size=4,
        address=True,
    )
    external_value = node("reg:isr:0", "value:external", size=4)
    return {
        "binary": "/nonexistent/precision.elf",
        "memory_blocks": [
            {
                "name": ".bss",
                "start": "0x20000000",
                "end": "0x2000003f",
                "read": True,
                "write": True,
                "execute": False,
            }
        ],
        "symbols": [
            {
                "name": "shared",
                "address": "0x20000000",
                "size": 32,
                "source": "ELF",
                "object_id": "global:20000000",
            },
            {
                "name": "after_shared",
                "address": "0x20000020",
                "size": 32,
                "source": "ELF",
                "object_id": "global:20000020",
            },
        ],
        "functions": [
            {
                "function_id": "fn:writer",
                "name": "interrupt_entry",
                "is_interrupt_entry": True,
                "pcode_ops": [
                    {
                        "site_id": "site:source-load",
                        "mnemonic": "LOAD",
                        "output": external_value,
                        "inputs": [
                            node("const:space", "const:space", constant=True),
                            node(
                                "const:40000000:4",
                                "const:40000000:4",
                                space="const",
                                offset="0x40000000",
                                constant=True,
                            ),
                        ],
                    },
                    {
                        "site_id": "site:source-store",
                        "mnemonic": "STORE",
                        "inputs": [
                            node("const:space2", "const:space2", constant=True),
                            shared_write,
                            external_value,
                        ],
                    },
                ],
            },
            {
                "function_id": "fn:reader",
                "name": reader_name,
                "is_interrupt_entry": False,
                "pcode_ops": [
                    {
                        "site_id": "site:shared-read",
                        "mnemonic": "LOAD",
                        "output": node("reg:reader:0", "value:read", size=2),
                        "inputs": [
                            node("const:space3", "const:space3", constant=True),
                            shared_read,
                        ],
                    }
                ],
            },
        ],
    }


def def_use_sources() -> dict:
    return {
        "source_definitions": [
            {
                "source_definition_id": "source-definition:one",
                "source_id": "SO1",
                "function_id": "fn:writer",
                "site_id": "site:source-load",
                "decision": "ACCEPT_DETERMINISTIC",
                "outputs": [
                    {
                        "role": "output_buffer",
                        "kind": "memory_object",
                        "object_id": "global:20000000",
                        "value_id": "value:external",
                        "binding_status": "high_pcode_value_bound",
                    }
                ],
                "proof": {
                    "kind": "high_pcode_def_use",
                    "site_binding_status": "verified_high_pcode_def_use_site",
                    "mmio_load_value_id": "value:external",
                    "memory_store_site_id": "site:source-store",
                },
            }
        ]
    }


def strict_parts(facts: dict, sources: dict):
    resolver = channel.DataObjectResolver(facts)
    objects, exact_edges, calls = channel.build_exact_graph(facts, resolver)
    writes, source_blockers = channel.derive_deterministic_source_writes(
        facts, sources, exact_edges, objects, resolver
    )
    strict_edges, pairing_blockers = channel.build_strict_channel_edges(
        writes, exact_edges
    )
    channel.classify_shared_object_candidates(objects, exact_edges + writes)
    channel.classify_deterministic_shared_objects(
        objects, strict_edges, source_blockers + pairing_blockers
    )
    return objects, exact_edges, calls, writes, strict_edges, source_blockers, pairing_blockers


class ChannelGraphPrecisionTests(unittest.TestCase):
    def test_multiequal_address_requires_unanimous_inputs(self) -> None:
        left = node(
            "global:20000000:4",
            "value:left",
            space="ram",
            offset="0x20000000",
            address=True,
        )
        right = node(
            "global:20000010:4",
            "value:right",
            space="ram",
            offset="0x20000010",
            address=True,
        )
        merged = node("reg:merged", "value:merged", def_site_id="site:merge")
        facts = {
            "binary": "",
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
            "symbols": [],
            "functions": [
                {
                    "function_id": "fn:merge",
                    "name": "merge",
                    "pcode_ops": [
                        {
                            "site_id": "site:merge",
                            "mnemonic": "MULTIEQUAL",
                            "output": merged,
                            "inputs": [left, right],
                        }
                    ],
                }
            ],
        }

        resolver = channel.DataObjectResolver(facts)

        self.assertIsNone(resolver.resolve_address(merged))
        facts["functions"][0]["pcode_ops"][0]["inputs"] = [left, dict(left)]
        resolver = channel.DataObjectResolver(facts)
        self.assertEqual(
            resolver.resolve_address(merged),
            (0x20000000, "SSA_MULTIEQUAL_UNANIMOUS"),
        )

    def test_dynamic_ptradd_preserves_base_without_guessing_index(self) -> None:
        base = node(
            "global:20000000:4",
            "value:base",
            space="ram",
            offset="0x20000000",
            address=True,
        )
        index = node("reg:index", "value:index")
        stride = node(
            "const:4:4",
            "const:4:4",
            space="const",
            offset="0x4",
            constant=True,
        )
        pointer = node("reg:pointer", "value:pointer", def_site_id="site:ptradd")
        facts = {
            "binary": "",
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
                    "name": "array",
                    "address": "0x20000000",
                    "size": 256,
                    "source": "ELF",
                    "object_id": "global:20000000",
                }
            ],
            "functions": [
                {
                    "function_id": "fn:index",
                    "name": "index",
                    "pcode_ops": [
                        {
                            "site_id": "site:ptradd",
                            "mnemonic": "PTRADD",
                            "output": pointer,
                            "inputs": [base, index, stride],
                        }
                    ],
                }
            ],
        }

        resolver = channel.DataObjectResolver(facts)
        binding = channel._memory_binding(
            pointer, "fn:index", 1, "HIGH_PCODE_CONCRETE_ACCESS", resolver
        )

        self.assertEqual(
            resolver.resolve_address(pointer),
            (0x20000000, "SSA_PTRADD_DYNAMIC_BASE"),
        )
        self.assertEqual(binding["region"]["offset"], 0)
        self.assertEqual(
            binding["region"]["selector_terms"],
            [{"selector_value_id": "value:index", "stride": 4}],
        )

    def test_affine_record_array_preserves_field_offset(self) -> None:
        base = node(
            "global:20400c:4",
            "value:base",
            space="ram",
            offset="0x200003f8",
            address=True,
        )
        index = node("reg:index", "value:index")
        stride = node(
            "const:c:4",
            "const:c:4",
            space="const",
            offset="0xc",
            constant=True,
        )
        field_offset = node(
            "const:4:4",
            "const:4:4",
            space="const",
            offset="0x4",
            constant=True,
        )
        scaled = node("reg:scaled", "value:scaled", def_site_id="site:scaled")
        record = node("reg:record", "value:record", def_site_id="site:record")
        field = node("reg:field", "value:field", def_site_id="site:field")
        facts = {
            "binary": "",
            "memory_blocks": [
                {
                    "name": ".bss",
                    "start": "0x20000000",
                    "end": "0x20000fff",
                    "read": True,
                    "write": True,
                    "execute": False,
                }
            ],
            "symbols": [
                {
                    "name": "events",
                    "address": "0x200003f8",
                    "size": 384,
                    "source": "ELF",
                    "object_id": "global:200003f8",
                }
            ],
            "functions": [
                {
                    "function_id": "fn:queue",
                    "name": "queue",
                    "pcode_ops": [
                        {
                            "site_id": "site:scaled",
                            "mnemonic": "INT_MULT",
                            "output": scaled,
                            "inputs": [index, stride],
                        },
                        {
                            "site_id": "site:record",
                            "mnemonic": "INT_ADD",
                            "output": record,
                            "inputs": [base, scaled],
                        },
                        {
                            "site_id": "site:field",
                            "mnemonic": "INT_ADD",
                            "output": field,
                            "inputs": [record, field_offset],
                        },
                    ],
                }
            ],
        }

        resolver = channel.DataObjectResolver(facts)
        binding = channel._memory_binding(
            field, "fn:queue", 4, "HIGH_PCODE_CONCRETE_ACCESS", resolver
        )

        self.assertEqual(
            resolver.resolve_address(record),
            (0x200003F8, "SSA_AFFINE_DYNAMIC_BASE"),
        )
        self.assertEqual(
            resolver.resolve_address(field),
            (0x200003FC, "SSA_INT_ADD"),
        )
        self.assertEqual(binding["region"]["offset"], 4)
        self.assertEqual(
            binding["region"]["selector_terms"],
            [{"selector_value_id": "value:index", "stride": 12}],
        )

    def test_affine_field_offset_before_static_base_is_preserved(self) -> None:
        base = node(
            "global:base:4",
            "value:base",
            space="ram",
            offset="0x20000000",
            address=True,
        )
        index = node("reg:index", "value:index")
        stride = node(
            "const:20:4",
            "const:20:4",
            space="const",
            offset="0x20",
            constant=True,
        )
        field_offset = node(
            "const:10:4",
            "const:10:4",
            space="const",
            offset="0x10",
            constant=True,
        )
        scaled = node("reg:scaled", "value:scaled", def_site_id="site:scaled")
        indexed_field = node(
            "reg:indexed-field",
            "value:indexed-field",
            def_site_id="site:indexed-field",
        )
        pointer = node(
            "reg:pointer", "value:pointer", def_site_id="site:pointer"
        )
        facts = {
            "binary": "",
            "memory_blocks": [
                {
                    "name": ".bss",
                    "start": "0x20000000",
                    "end": "0x20000fff",
                    "read": True,
                    "write": True,
                    "execute": False,
                }
            ],
            "symbols": [
                {
                    "name": "records",
                    "address": "0x20000000",
                    "size": 4096,
                    "source": "ELF",
                    "object_id": "global:20000000",
                }
            ],
            "functions": [
                {
                    "function_id": "fn:records",
                    "name": "records",
                    "pcode_ops": [
                        {
                            "site_id": "site:scaled",
                            "mnemonic": "INT_MULT",
                            "output": scaled,
                            "inputs": [index, stride],
                        },
                        {
                            "site_id": "site:indexed-field",
                            "mnemonic": "INT_ADD",
                            "output": indexed_field,
                            "inputs": [scaled, field_offset],
                        },
                        {
                            "site_id": "site:pointer",
                            "mnemonic": "INT_ADD",
                            "output": pointer,
                            "inputs": [base, indexed_field],
                        },
                    ],
                }
            ],
        }

        resolver = channel.DataObjectResolver(facts)
        binding = channel._memory_binding(
            pointer,
            "fn:records",
            4,
            "HIGH_PCODE_CONCRETE_ACCESS",
            resolver,
        )

        self.assertEqual(
            resolver.resolve_address(pointer),
            (0x20000010, "SSA_AFFINE_DYNAMIC_BASE"),
        )
        self.assertEqual(binding["region"]["offset"], 0x10)
        self.assertEqual(
            binding["region"]["selector_terms"],
            [{"selector_value_id": "value:index", "stride": 0x20}],
        )

    def test_static_buffer_plus_runtime_byte_offset_keeps_aggregate(self) -> None:
        base = node(
            "global:buffer:4",
            "value:buffer",
            space="ram",
            offset="0x20000100",
            address=True,
        )
        offset = node("reg:offset", "value:offset")
        pointer = node(
            "reg:pointer", "value:pointer", def_site_id="site:pointer"
        )
        facts = {
            "binary": "",
            "memory_blocks": [
                {
                    "name": ".bss",
                    "start": "0x20000000",
                    "end": "0x20000fff",
                    "read": True,
                    "write": True,
                    "execute": False,
                }
            ],
            "symbols": [
                {
                    "name": "packet_buffer",
                    "address": "0x20000100",
                    "size": 128,
                    "source": "ELF",
                    "object_id": "global:20000100",
                }
            ],
            "functions": [
                {
                    "function_id": "fn:accessor",
                    "name": "accessor",
                    "pcode_ops": [
                        {
                            "site_id": "site:pointer",
                            "mnemonic": "INT_ADD",
                            "output": pointer,
                            "inputs": [base, offset],
                        }
                    ],
                }
            ],
        }

        resolver = channel.DataObjectResolver(facts)
        binding = channel._memory_binding(
            pointer,
            "fn:accessor",
            1,
            "SYMBOLIC_NONZERO_WITNESS",
            resolver,
        )

        self.assertEqual(
            resolver.resolve_address(pointer),
            (0x20000100, "SSA_AFFINE_DYNAMIC_BASE"),
        )
        self.assertEqual(
            binding["region"]["selector_terms"],
            [{"selector_value_id": "value:offset", "stride": 1}],
        )

    def test_missing_channel_atom_is_not_traversable(self) -> None:
        normalized = channel.normalize_channel_edge_v4(
            {
                "edge_id": "channel:missing",
                "edge_kind": "CHANNEL_WRITE",
                "src_node_id": "fn:writer",
                "dst_node_id": "obj:buffer",
                "object_id": "obj:buffer",
                "site_id": "site:write",
            }
        )

        self.assertFalse(normalized["traversable"])
        self.assertEqual(normalized["stored_atom_id"], "")
        self.assertIn(
            "channel_write_stored_atom_missing",
            normalized["analysis_blockers"],
        )

    def test_unique_resolved_callind_becomes_typed_call_edge(self) -> None:
        facts = {
            "functions": [
                {
                    "function_id": "fn:caller",
                    "name": "caller",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:callind",
                            "mnemonic": "CALLIND",
                            "inputs": [
                                node("reg:target", "value:target"),
                                node("param:caller:0", "value:actual"),
                            ],
                            "call": {
                                "argument_value_ids": ["value:actual"],
                                "argument_object_ids": ["param:caller:0"],
                            },
                        }
                    ],
                },
                {
                    "function_id": "fn:callee",
                    "name": "callee",
                    "parameters": [
                        {"index": 0, "name": "out", "object_id": "param:callee:0"}
                    ],
                    "pcode_ops": [],
                },
            ]
        }
        resolution = {
            "resolved": [
                {
                    "status": "resolved",
                    "resolution_kind": "constant_api_table",
                    "callsite": {"site_id": "site:callind"},
                    "target": {
                        "function_id": "fn:callee",
                        "function": "callee",
                    },
                    "evidence": [{"kind": "initialized_table_slot"}],
                }
            ]
        }

        self.assertEqual(channel.apply_resolved_dispatch_targets(facts, resolution), 1)
        _objects, _accesses, calls = channel.build_exact_graph(facts)

        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["dst_node_id"], "fn:callee")
        self.assertEqual(calls[0]["resolution"], "EXACT_INDIRECT_TARGET")
        self.assertEqual(calls[0]["formal_parameter_object_ids"], ["param:callee:0"])
        self.assertEqual(calls[0]["argument_value_ids"], ["value:actual"])

    def test_def_use_write_and_overlapping_read_form_strict_region_channel(self) -> None:
        parts = strict_parts(memory_facts(), def_use_sources())
        objects, exact, calls, writes, strict, source_blockers, pair_blockers = parts

        exact_write = next(edge for edge in exact if edge["edge_kind"] == "OBJECT_WRITE")
        exact_read = next(edge for edge in exact if edge["edge_kind"] == "OBJECT_READ")
        self.assertEqual(exact_write["base_object_id"], "obj:ram:20000000")
        self.assertEqual((exact_write["region_offset"], exact_write["region_extent"]), (4, 4))
        self.assertEqual((exact_read["region_offset"], exact_read["region_extent"]), (6, 2))
        self.assertEqual({edge["edge_kind"] for edge in strict}, {"CHANNEL_WRITE", "CHANNEL_READ"})
        self.assertEqual(writes[0]["source_definition_id"], "source-definition:one")
        write = next(edge for edge in strict if edge["edge_kind"] == "CHANNEL_WRITE")
        self.assertEqual(write["overlap_evidence"][0]["offset"], 6)
        self.assertEqual(write["overlap_evidence"][0]["extent"], 2)
        self.assertEqual(source_blockers, [])
        self.assertEqual(pair_blockers, [])
        self.assertEqual(calls, [])
        shared = [obj for obj in objects if obj.get("shared_object")]
        self.assertEqual(len(shared), 1)
        self.assertTrue(shared[0]["writable"])
        self.assertFalse(shared[0]["is_stack"])
        self.assertFalse(shared[0]["is_rom"])

        artifact = {
            "schema_version": "ct-mini-channel-graph-v2",
            "strict_traversal_surface": "channel_edges",
            "function_nodes": [],
            "object_nodes": objects,
            "nodes": [
                {**obj, "node_kind": "SHARED_OBJECT"}
                for obj in objects
                if obj.get("strict_shared_object")
            ],
            "edges": strict,
            "call_edges": calls,
            "channel_edges": strict,
            "candidate_channel_edges": exact + writes,
            "channel_blockers": [],
            "counts": {},
        }
        schema = json.loads((ROOT / "schemas/channel_graph.v2.schema.json").read_text())
        Draft202012Validator(schema).validate(artifact)

    def test_heuristic_rows_and_unsupported_proofs_never_promote(self) -> None:
        facts = memory_facts()
        heuristic_only = {
            "source_sites": [
                {
                    "id": "CVE-NAMED-SOURCE",
                    "function": "interrupt_entry",
                    "score": 1.0,
                    "decision": "ACCEPT_DETERMINISTIC",
                    "source_object_id": "global:20000000",
                    "source_value_id": "value:external",
                }
            ]
        }
        self.assertEqual(strict_parts(facts, heuristic_only)[3], [])

        unsupported = def_use_sources()
        definition = unsupported["source_definitions"][0]
        definition["proof"] = {"kind": "generalized_name_score_heuristic"}
        definition["cve_id"] = "CVE-2099-0001"
        definition["score"] = 1.0
        parts = strict_parts(facts, unsupported)
        self.assertEqual(parts[3], [])
        self.assertEqual(parts[5][0]["reason"], "unsupported_source_definition_memory_proof")

    def test_profile_dma_source_is_not_misreported_as_missing_cpu_store(self) -> None:
        sources = def_use_sources()
        sources["source_definitions"][0]["proof"] = {
            "kind": "high_pcode_profile_dma_binding",
            "destination_store_site_id": "site:dma-packetptr",
            "destination_object_id": "global:20000000",
        }

        parts = strict_parts(memory_facts(), sources)

        self.assertEqual(parts[3], [])
        self.assertEqual(parts[5], [])

    def test_nonoverlap_and_name_only_task_context_are_blocked(self) -> None:
        nonoverlap = strict_parts(memory_facts(read_offset=12), def_use_sources())
        self.assertEqual(nonoverlap[4], [])
        self.assertEqual(nonoverlap[6][0]["reason"], "no_overlapping_read_region")

        task_named = strict_parts(
            memory_facts(reader_name="packet_worker_task"), def_use_sources()
        )
        self.assertEqual(task_named[4], [])
        self.assertEqual(
            task_named[6][0]["reason"],
            "overlapping_read_context_not_singleton_deterministic",
        )

    def test_body_summary_requires_exact_actual_binding_and_extent(self) -> None:
        facts = memory_facts()
        pointer = node(
            "global:20000004:4",
            "value:summary-pointer",
            space="ram",
            offset="0x20000004",
            address=True,
        )
        facts["functions"][0] = {
            "function_id": "fn:writer",
            "name": "main",
            "is_interrupt_entry": False,
            "pcode_ops": [
                {
                    "site_id": "site:summary-call",
                    "mnemonic": "CALL",
                    "inputs": [
                        node("const:target", "const:target", constant=True),
                        pointer,
                    ],
                    "call": {"target_function_id": "fn:callee"},
                }
            ],
        }
        facts["functions"][1]["name"] = "interrupt_reader"
        facts["functions"][1]["is_interrupt_entry"] = True
        facts["functions"].append(
            {"function_id": "fn:callee", "name": "callee", "pcode_ops": []}
        )
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:summary",
                    "source_id": "SO-SUMMARY",
                    "function_id": "fn:writer",
                    "site_id": "site:summary-call",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "outputs": [
                        {
                            "role": "output_buffer",
                            "kind": "memory_object",
                            "object_id": "global:20000004:4",
                            "value_id": "value:summary-pointer",
                            "binding_status": "high_pcode_value_bound",
                            "extent": 4,
                        }
                    ],
                    "proof": {
                        "kind": "high_pcode_function_summary",
                        "call_site_id": "site:summary-call",
                        "callee_function_id": "fn:callee",
                        "actual_value_id": "value:summary-pointer",
                        "callee_output_bindings": [
                            {
                                "role": "output_buffer",
                                "binding_kind": "formal_pointee",
                                "parameter_slot": 0,
                            }
                        ],
                    },
                }
            ]
        }
        parts = strict_parts(facts, sources)
        self.assertEqual(parts[5], [])
        self.assertEqual(parts[6], [])
        self.assertEqual(parts[3][0]["source_binding_kind"], "DIRECT_ACTUAL_FORMAL_BODY_SUMMARY")
        self.assertEqual({edge["edge_kind"] for edge in parts[4]}, {"CHANNEL_WRITE", "CHANNEL_READ"})

        del sources["source_definitions"][0]["outputs"][0]["extent"]
        blocked = strict_parts(facts, sources)
        self.assertEqual(blocked[3], [])
        self.assertEqual(
            blocked[5][0]["reason"], "source_summary_region_or_extent_not_unique"
        )

    def test_exact_call_return_source_summary_can_bind_region(self) -> None:
        facts = memory_facts()
        returned_pointer = node(
            "reg:return:0",
            "value:return-pointer",
            def_site_id="site:return-call",
        )
        global_pointer = node(
            "global:20000004:4",
            "value:global-pointer",
            space="ram",
            offset="0x20000004",
            address=True,
        )
        facts["functions"][0] = {
            "function_id": "fn:writer",
            "name": "main",
            "pcode_ops": [
                {
                    "site_id": "site:return-call",
                    "mnemonic": "CALL",
                    "output": returned_pointer,
                    "inputs": [node("const:target", "const:target", constant=True)],
                    "call": {"target_function_id": "fn:callee"},
                }
            ],
        }
        facts["functions"][1]["name"] = "interrupt_reader"
        facts["functions"][1]["is_interrupt_entry"] = True
        facts["functions"].append(
            {
                "function_id": "fn:callee",
                "name": "callee",
                "pcode_ops": [
                    {
                        "site_id": "site:callee-return",
                        "mnemonic": "RETURN",
                        "inputs": [
                            node("const:return", "const:return", constant=True),
                            global_pointer,
                        ],
                    }
                ],
            }
        )
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:return",
                    "source_id": "SO-RETURN",
                    "function_id": "fn:writer",
                    "site_id": "site:return-call",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "outputs": [
                        {
                            "role": "return_pointer",
                            "kind": "memory_object",
                            "object_id": "pointee:value:return-pointer",
                            "value_id": "value:return-pointer",
                            "binding_status": "exact_call_return",
                            "extent": 4,
                        }
                    ],
                    "proof": {
                        "kind": "software_interface_summary_instantiation",
                        "call_site_id": "site:return-call",
                        "callee_function_id": "fn:callee",
                        "summary_proof_kind": "body_proved_hardware_provenance",
                    },
                }
            ]
        }
        parts = strict_parts(facts, sources)
        self.assertEqual(parts[5], [])
        self.assertEqual(parts[6], [])
        self.assertEqual(parts[3][0]["source_binding_kind"], "EXACT_CALL_RETURN")
        self.assertEqual({edge["edge_kind"] for edge in parts[4]}, {"CHANNEL_WRITE", "CHANNEL_READ"})

    def test_local_forward_def_use_promotes_later_store_and_blocks_unknown_region(self) -> None:
        facts = memory_facts(read_offset=18)
        source_value = node("reg:writer:0", "value:source-scalar", size=4)
        copied_value = node("reg:writer:1", "value:source-copy", size=4)
        later_address = node(
            "global:20000010:4",
            "value:later-address",
            space="ram",
            offset="0x20000010",
            address=True,
        )
        unresolved_address = node("reg:writer:address", "value:unknown-address")
        facts["functions"][0]["pcode_ops"] = [
            {
                "site_id": "site:scalar-source",
                "mnemonic": "LOAD",
                "output": source_value,
                "inputs": [
                    node("const:space", "const:space", constant=True),
                    node(
                        "const:40000000:4",
                        "const:40000000:4",
                        space="const",
                        offset="0x40000000",
                        constant=True,
                    ),
                ],
            },
            {
                "site_id": "site:source-copy",
                "mnemonic": "COPY",
                "output": copied_value,
                "inputs": [source_value],
            },
            {
                "site_id": "site:later-store",
                "mnemonic": "STORE",
                "inputs": [
                    node("const:space2", "const:space2", constant=True),
                    later_address,
                    copied_value,
                ],
            },
            {
                "site_id": "site:unresolved-store",
                "mnemonic": "STORE",
                "inputs": [
                    node("const:space3", "const:space3", constant=True),
                    unresolved_address,
                    copied_value,
                ],
            },
        ]
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:scalar",
                    "source_id": "SO-SCALAR",
                    "function_id": "fn:writer",
                    "site_id": "site:scalar-source",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "outputs": [
                        {
                            "role": "return_value",
                            "kind": "scalar_value",
                            "object_id": "reg:writer:0",
                            "value_id": "value:source-scalar",
                            "binding_status": "exact_value",
                        }
                    ],
                    "proof": {"kind": "high_pcode_mmio_value_def_use"},
                }
            ]
        }
        parts = strict_parts(facts, sources)
        self.assertEqual(len(parts[3]), 1)
        self.assertEqual(parts[3][0]["site_id"], "site:later-store")
        self.assertEqual(
            parts[3][0]["source_binding_kind"], "FORWARD_HIGH_PCODE_PROVENANCE"
        )
        transfers = parts[3][0]["source_provenance"]["transfers"]
        self.assertIn("LOCAL_HIGH_PCODE_DEF_USE", {row["kind"] for row in transfers})
        self.assertEqual({edge["edge_kind"] for edge in parts[4]}, {"CHANNEL_WRITE", "CHANNEL_READ"})
        self.assertIn(
            "source_derived_store_region_unresolved",
            {row["reason"] for row in parts[5]},
        )

    def test_direct_actual_formal_and_return_fixed_point_promotes_caller_store(self) -> None:
        facts = memory_facts(read_offset=18)
        source_value = node("reg:writer:0", "value:source-scalar", size=4)
        returned_value = node(
            "reg:writer:1",
            "value:returned-source",
            size=4,
            def_site_id="site:helper-call",
        )
        formal = node("param:helper:0", "value:helper-formal", size=4)
        formal["is_parameter"] = True
        formal["parameter_slot"] = 0
        later_address = node(
            "global:20000010:4",
            "value:later-address",
            space="ram",
            offset="0x20000010",
            address=True,
        )
        facts["functions"][0] = {
            "function_id": "fn:writer",
            "name": "main",
            "parameters": [],
            "pcode_ops": [
                {
                    "site_id": "site:scalar-source",
                    "mnemonic": "LOAD",
                    "output": source_value,
                    "inputs": [
                        node("const:space", "const:space", constant=True),
                        node(
                            "const:40000000:4",
                            "const:40000000:4",
                            space="const",
                            offset="0x40000000",
                            constant=True,
                        ),
                    ],
                },
                {
                    "site_id": "site:helper-call",
                    "mnemonic": "CALL",
                    "output": returned_value,
                    "inputs": [
                        node("const:helper", "const:helper", constant=True),
                        source_value,
                    ],
                    "call": {"target_function_id": "fn:helper"},
                },
                {
                    "site_id": "site:returned-store",
                    "mnemonic": "STORE",
                    "inputs": [
                        node("const:space2", "const:space2", constant=True),
                        later_address,
                        returned_value,
                    ],
                },
            ],
        }
        facts["functions"][1]["name"] = "interrupt_reader"
        facts["functions"][1]["is_interrupt_entry"] = True
        facts["functions"].append(
            {
                "function_id": "fn:helper",
                "name": "helper",
                "parameters": [
                    {"index": 0, "object_id": "param:helper:0", "name": "value"}
                ],
                "pcode_ops": [
                    {
                        "site_id": "site:helper-return",
                        "mnemonic": "RETURN",
                        "inputs": [
                            node("const:return", "const:return", constant=True),
                            formal,
                        ],
                    }
                ],
            }
        )
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:scalar-call",
                    "source_id": "SO-SCALAR-CALL",
                    "function_id": "fn:writer",
                    "site_id": "site:scalar-source",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "outputs": [
                        {
                            "role": "return_value",
                            "kind": "scalar_value",
                            "object_id": "reg:writer:0",
                            "value_id": "value:source-scalar",
                            "binding_status": "exact_value",
                        }
                    ],
                    "proof": {"kind": "high_pcode_mmio_value_def_use"},
                }
            ]
        }
        parts = strict_parts(facts, sources)
        self.assertEqual(parts[5], [])
        self.assertEqual(parts[6], [])
        self.assertEqual(len(parts[3]), 1)
        transfer_kinds = {
            row["kind"]
            for row in parts[3][0]["source_provenance"]["transfers"]
        }
        self.assertIn("DIRECT_CALL_ACTUAL_FORMAL", transfer_kinds)
        self.assertIn("DIRECT_CALL_RETURN", transfer_kinds)
        self.assertEqual({edge["edge_kind"] for edge in parts[4]}, {"CHANNEL_WRITE", "CHANNEL_READ"})

    def test_body_proved_copy_summary_propagates_prior_source_region(self) -> None:
        facts = memory_facts(read_offset=18)
        destination = node(
            "global:20000010:4",
            "value:copy-destination",
            space="ram",
            offset="0x20000010",
            address=True,
        )
        source = node(
            "global:20000004:4",
            "value:copy-source",
            space="ram",
            offset="0x20000004",
            address=True,
        )
        facts["functions"][0]["pcode_ops"].append(
            {
                "site_id": "site:body-copy",
                "mnemonic": "CALL",
                "inputs": [
                    node("const:copy", "const:copy", constant=True),
                    destination,
                    source,
                    node(
                        "const:4:4",
                        "const:4:4",
                        space="const",
                        offset="0x4",
                        constant=True,
                    ),
                ],
                "call": {"target_function_id": "fn:copy"},
            }
        )
        facts["functions"].append(
            {"function_id": "fn:copy", "name": "opaque_copy", "pcode_ops": []}
        )
        sources = def_use_sources()
        sources["body_proved_copy_summaries"] = [
            {
                "summary_id": "summary:copy",
                "function_id": "fn:copy",
                "proof_kind": "body_proved_copy",
                "destination_parameter_slot": 0,
                "source_parameter_slot": 1,
                "size_parameter_slot": 2,
            }
        ]

        parts = strict_parts(facts, sources)

        copy_writes = [
            write
            for write in parts[3]
            if write.get("source_binding_kind") == "BODY_PROVED_COPY_SUMMARY"
        ]
        self.assertEqual(len(copy_writes), 1)
        self.assertEqual(copy_writes[0]["region_offset"], 16)
        self.assertIn(
            "BODY_PROVED_COPY_SUMMARY",
            {
                row["kind"]
                for row in copy_writes[0]["source_provenance"]["transfers"]
            },
        )
        strict_write = next(
            edge
            for edge in parts[4]
            if edge["edge_kind"] == "CHANNEL_WRITE"
        )
        self.assertEqual(strict_write["region_offset"], 16)

        clobbered_facts = json.loads(json.dumps(facts))
        clobbered_facts["functions"][0]["pcode_ops"].insert(
            2,
            {
                "site_id": "site:source-clobber",
                "mnemonic": "STORE",
                "inputs": [
                    node("const:space4", "const:space4", constant=True),
                    source,
                    node(
                        "const:0:4",
                        "const:0:4",
                        space="const",
                        offset="0x0",
                        size=4,
                        constant=True,
                    ),
                ],
            },
        )
        blocked = strict_parts(clobbered_facts, sources)
        self.assertFalse(
            any(
                write.get("source_binding_kind") == "BODY_PROVED_COPY_SUMMARY"
                for write in blocked[3]
            )
        )
        self.assertIn(
            "body_proved_copy_reaching_write_clobbered",
            {row["reason"] for row in blocked[5]},
        )

    def test_cli_artifact_keeps_candidates_out_of_strict_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            facts_path = Path(tmp) / "facts.json"
            sources_path = Path(tmp) / "sources.json"
            output_path = Path(tmp) / "channel_graph.json"
            facts_path.write_text(json.dumps(memory_facts()))
            sources_path.write_text(json.dumps(def_use_sources()))
            argv = [
                "build_channel_graph_v2.py",
                "--program-facts",
                str(facts_path),
                "--sources-json",
                str(sources_path),
                "--output",
                str(output_path),
            ]
            empty_legacy = {"schema_version": "legacy-test", "params": {}, "object_nodes": []}
            with (
                patch.object(channel, "build_channel_graph", return_value=empty_legacy),
                patch.object(sys, "argv", argv),
                patch("builtins.print"),
            ):
                self.assertEqual(channel.main(), 0)

            artifact = json.loads(output_path.read_text())
            self.assertEqual(artifact["strict_traversal_surface"], "channel_edges")
            self.assertEqual(
                artifact["edges"], artifact["call_edges"] + artifact["channel_edges"]
            )
            self.assertTrue(
                all(
                    node.get("node_kind") in {"FUNCTION", "SHARED_OBJECT"}
                    for node in artifact["nodes"]
                )
            )
            self.assertEqual(
                {edge["edge_kind"] for edge in artifact["channel_edges"]},
                {"CHANNEL_WRITE", "CHANNEL_READ"},
            )
            self.assertTrue(artifact["candidate_channel_edges"])
            self.assertEqual(
                {
                    edge["edge_kind"]
                    for edge in artifact["candidate_channel_edges"]
                },
                {"OBJECT_WRITE", "OBJECT_READ"},
            )
            self.assertTrue(
                all(not edge["traversable"] for edge in artifact["candidate_channel_edges"])
            )
            schema = json.loads(
                (ROOT / "schemas/channel_graph.v4.schema.json").read_text()
            )
            Draft202012Validator(schema).validate(artifact)


if __name__ == "__main__":
    unittest.main()
