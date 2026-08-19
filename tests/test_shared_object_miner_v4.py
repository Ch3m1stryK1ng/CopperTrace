from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import memory_access_facts  # noqa: E402
import shared_object_miner  # noqa: E402


def access_index(
    *,
    same_function: bool = False,
    write_offset: int | None = 0,
    read_offset: int | None = 0,
    dynamic_selectors: bool = False,
    deterministic_contexts: bool = True,
    same_deterministic_context: bool = False,
) -> memory_access_facts.MemoryAccessFactIndex:
    object_id = "obj:ram:20000100"
    objects = [{"object_id": object_id, "storage_kind": "ABSOLUTE_SRAM"}]
    write_deterministic = ["ctx:isr"] if deterministic_contexts else []
    read_deterministic = (
        ["ctx:isr"]
        if deterministic_contexts and same_deterministic_context
        else ["ctx:task"]
        if deterministic_contexts
        else []
    )
    write_selectors = (
        [{"selector_value_id": "value:head", "stride": 1}]
        if dynamic_selectors
        else []
    )
    read_selectors = (
        [{"selector_value_id": "value:tail", "stride": 1}]
        if dynamic_selectors
        else []
    )
    edges = [
        {
            "edge_id": "access:source-write",
            "edge_kind": "OBJECT_WRITE",
            "site_id": "site:source-write",
            "function_id": "fn:writer",
            "object_id": object_id,
            "base_object_id": object_id,
            "value_id": "value:source",
            "access_width": 1,
            "region_offset": write_offset,
            "region_extent": 1,
            "selector_terms": write_selectors,
            "candidate_class": "EXACT_HIGH_PCODE_MEMORY_ACCESS",
            "deterministic_context_ids": write_deterministic,
            "context_ids": ["ctx:name-rx-worker"],
        },
        {
            "edge_id": "access:constant-write",
            "edge_kind": "OBJECT_WRITE",
            "site_id": "site:constant-write",
            "function_id": "fn:initializer",
            "object_id": object_id,
            "base_object_id": object_id,
            "value_id": "const:0:1",
            "access_width": 1,
            "region_offset": write_offset,
            "region_extent": 1,
            "selector_terms": write_selectors,
            "candidate_class": "EXACT_HIGH_PCODE_MEMORY_ACCESS",
            "deterministic_context_ids": ["ctx:init"],
        },
        {
            "edge_id": "access:read",
            "edge_kind": "OBJECT_READ",
            "site_id": "site:read",
            "function_id": "fn:writer" if same_function else "fn:reader",
            "object_id": object_id,
            "base_object_id": object_id,
            "value_id": "value:loaded",
            "access_width": 1,
            "region_offset": read_offset,
            "region_extent": 1,
            "selector_terms": read_selectors,
            "candidate_class": "EXACT_HIGH_PCODE_MEMORY_ACCESS",
            "deterministic_context_ids": read_deterministic,
            "context_ids": ["ctx:name-parser-task"],
        },
    ]
    return memory_access_facts.MemoryAccessFactIndex.from_exact_edges(edges, objects)


def source_associations() -> list[dict]:
    return [
        {
            "association_id": "association:1",
            "source_definition_id": "source-definition:1",
            "source_id": "SO1",
            "state_kind": "VALUE",
            "function_id": "fn:writer",
            "atom_id": "value:source",
            "site_id": "site:source",
            "precision": "EXACT",
            "channel_depth": 0,
        },
        {
            "association_id": "association:2",
            "source_definition_id": "source-definition:1",
            "source_id": "SO1",
            "state_kind": "MEMORY_CONTENT",
            "function_id": "fn:writer",
            "atom_id": "value:source",
            "object_id": "obj:ram:20000100",
            "site_id": "site:source-write",
            "relation_kind": "CONCRETE_STORE_VALUE",
            "precision": "EXACT",
            "channel_depth": 0,
        },
    ]


class SharedObjectMinerV4Tests(unittest.TestCase):
    def test_source_associated_body_proved_transport_is_admitted(self) -> None:
        object_id = "obj:transport:payload"
        evidence = {
            "submission_chain": [
                {
                    "function_id": "fn:submitter",
                    "site_id": "site:submit",
                    "payload_atom_id": "value:packet",
                }
            ],
            "dequeue_dispatch_consumers": [
                {
                    "function_id": "fn:dispatcher",
                    "callback_call_site_id": "site:dispatch",
                }
            ],
        }
        result = (
            shared_object_miner.mine_source_associated_transport_objects(
                [
                    {
                        "node_id": object_id,
                        "object_id": object_id,
                        "base_object_id": object_id,
                    }
                ],
                [
                    {
                        "edge_id": "transport:write",
                        "edge_kind": "CHANNEL_WRITE",
                        "object_id": object_id,
                        "src_node_id": "fn:submitter",
                        "site_id": "site:submit",
                        "value_atom_id": "value:packet",
                        "evidence": evidence,
                    },
                    {
                        "edge_id": "transport:read",
                        "edge_kind": "CHANNEL_READ",
                        "object_id": object_id,
                        "dst_node_id": "fn:consumer",
                        "site_id": "site:consume",
                        "value_atom_id": "value:consumer-parameter",
                        "evidence": evidence,
                    },
                ],
                [
                    {
                        "association_id": "association:packet",
                        "source_definition_id": "source-definition:1",
                        "source_id": "SO1",
                        "state_kind": "OBJECT_REFERENCE",
                        "function_id": "fn:submitter",
                        "atom_id": "value:packet",
                        "pointee_object_id": "obj:allocation:packet",
                        "precision": "MAY",
                        "channel_depth": 0,
                    }
                ],
            )
        )

        self.assertEqual(result["blockers"], [])
        self.assertEqual(len(result["shared_objects"]), 1)
        shared = result["shared_objects"][0]
        self.assertEqual(shared["recognition"], "heuristic")
        self.assertEqual(
            shared["transfer_semantics"], "OBJECT_REFERENCE"
        )
        self.assertEqual(
            shared["reference_binding"]["pointee_object_id"],
            "obj:allocation:packet",
        )
        edges = shared_object_miner.materialize_channel_edges(
            result["shared_objects"]
        )
        self.assertEqual(
            {edge["edge_kind"] for edge in edges},
            {"CHANNEL_WRITE", "CHANNEL_READ"},
        )
        self.assertTrue(
            next(
                edge
                for edge in edges
                if edge["edge_kind"] == "CHANNEL_WRITE"
            )["source_associated"]
        )

    def test_body_proved_transport_without_source_is_not_admitted(self) -> None:
        result = (
            shared_object_miner.mine_source_associated_transport_objects(
                [{"object_id": "obj:transport:payload"}],
                [
                    {
                        "edge_id": "transport:write",
                        "edge_kind": "CHANNEL_WRITE",
                        "object_id": "obj:transport:payload",
                        "src_node_id": "fn:submitter",
                        "site_id": "site:submit",
                        "value_atom_id": "value:packet",
                        "evidence": {
                            "submission_chain": [{"site_id": "site:submit"}],
                            "dequeue_dispatch_consumers": [
                                {"callback_call_site_id": "site:dispatch"}
                            ],
                        },
                    },
                    {
                        "edge_id": "transport:read",
                        "edge_kind": "CHANNEL_READ",
                        "object_id": "obj:transport:payload",
                        "dst_node_id": "fn:consumer",
                        "site_id": "site:consume",
                        "value_atom_id": "value:consumer-parameter",
                    },
                ],
                [],
            )
        )

        self.assertEqual(result["shared_objects"], [])
        self.assertEqual(
            result["rejected_candidates"][0]["admission_blockers"],
            ["transport_writer_has_no_source_association"],
        )

    def test_source_write_admits_object_and_retains_all_writers(self) -> None:
        result = shared_object_miner.mine_source_associated_shared_objects(
            access_index(), source_associations()
        )

        self.assertEqual(len(result["shared_objects"]), 1)
        shared = result["shared_objects"][0]
        self.assertEqual(shared["transfer_semantics"], "MEMORY_CONTENT")
        self.assertEqual(shared["recognition"], "deterministic")
        self.assertEqual(shared["region_relation"], "EXACT_OVERLAP")
        self.assertEqual(len(shared["writers"]), 2)
        self.assertEqual(
            {
                row["site_id"]: row["source_associated"]
                for row in shared["writers"]
            },
            {
                "site:source-write": True,
                "site:constant-write": False,
            },
        )
        edges = shared_object_miner.materialize_channel_edges(
            result["shared_objects"]
        )
        constant = next(
            edge
            for edge in edges
            if edge["site_id"] == "site:constant-write"
        )
        self.assertEqual(constant["source_id"], "")
        self.assertFalse(constant["source_associated"])

    def test_same_function_read_does_not_admit_shared_object(self) -> None:
        result = shared_object_miner.mine_source_associated_shared_objects(
            access_index(same_function=True), source_associations()
        )

        self.assertEqual(result["shared_objects"], [])
        self.assertIn(
            "source_associated_object_has_only_same_function_reads",
            {row["reason"] for row in result["blockers"]},
        )

    def test_fixed_disjoint_regions_do_not_admit_shared_object(self) -> None:
        result = shared_object_miner.mine_source_associated_shared_objects(
            access_index(write_offset=0, read_offset=16),
            source_associations(),
        )

        self.assertEqual(result["shared_objects"], [])
        self.assertIn(
            "source_associated_object_has_only_disjoint_read_regions",
            {row["reason"] for row in result["blockers"]},
        )

    def test_dynamic_head_tail_is_may_overlap_and_heuristic(self) -> None:
        result = shared_object_miner.mine_source_associated_shared_objects(
            access_index(
                write_offset=None,
                read_offset=None,
                dynamic_selectors=True,
            ),
            source_associations(),
        )

        self.assertEqual(len(result["shared_objects"]), 1)
        shared = result["shared_objects"][0]
        self.assertEqual(shared["region_relation"], "MAY_OVERLAP")
        self.assertEqual(shared["analysis_precision"], "MAY")
        self.assertEqual(shared["recognition"], "heuristic")
        self.assertEqual(
            shared["readers"][0]["region_relation"], "MAY_OVERLAP"
        )

    def test_heuristic_context_names_cannot_become_deterministic(self) -> None:
        result = shared_object_miner.mine_source_associated_shared_objects(
            access_index(deterministic_contexts=False),
            source_associations(),
        )

        self.assertEqual(len(result["shared_objects"]), 1)
        shared = result["shared_objects"][0]
        self.assertEqual(shared["recognition"], "heuristic")
        self.assertEqual(
            shared["readers"][0]["context_relation"],
            "DISTINCT_FUNCTION_HEURISTIC_CONTEXT",
        )

    def test_same_deterministic_context_is_only_heuristic(self) -> None:
        result = shared_object_miner.mine_source_associated_shared_objects(
            access_index(same_deterministic_context=True),
            source_associations(),
        )

        self.assertEqual(len(result["shared_objects"]), 1)
        self.assertEqual(
            result["shared_objects"][0]["recognition"], "heuristic"
        )


if __name__ == "__main__":
    unittest.main()
