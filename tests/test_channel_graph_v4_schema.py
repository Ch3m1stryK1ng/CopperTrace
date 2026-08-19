import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "channel_graph.v4.schema.json"


def semantic_free_artifact() -> dict:
    call_edge = {
        "edge_id": "call:site:00001000:00001004",
        "src_node_id": "fn:00001000",
        "dst_node_id": "fn:00002000",
        "edge_kind": "CALL",
        "site_id": "site:00001000:00001004",
        "resolution": "DIRECT",
    }
    callind_edge = {
        "edge_id": "callind:site:00002000:00002008",
        "src_node_id": "fn:00002000",
        "dst_node_id": "fn:00003000",
        "edge_kind": "CALLIND",
        "site_id": "site:00002000:00002008",
        "resolution": "EXACT_INDIRECT_TARGET",
    }
    source_write = {
        "edge_id": "channel:write:00001010",
        "src_node_id": "fn:00001000",
        "dst_node_id": "obj:ram:20000100",
        "edge_kind": "CHANNEL_WRITE",
        "site_id": "site:00001000:00001010",
        "object_id": "obj:ram:20000100",
        "recognition": "deterministic",
        "source_associated": True,
        "traversable": True,
        "stored_atom_id": "atom:write:00001010",
        "transfer_semantics": "MEMORY_CONTENT",
    }
    internal_write = {
        "edge_id": "channel:write:00001020",
        "src_node_id": "fn:00001000",
        "dst_node_id": "obj:ram:20000100",
        "edge_kind": "CHANNEL_WRITE",
        "site_id": "site:00001000:00001020",
        "object_id": "obj:ram:20000100",
        "recognition": "deterministic",
        "source_associated": False,
        "traversable": True,
        "stored_atom_id": "atom:constant:00001020",
        "transfer_semantics": "MEMORY_CONTENT",
    }
    read_edge = {
        "edge_id": "channel:read:00002010",
        "src_node_id": "obj:ram:20000100",
        "dst_node_id": "fn:00002000",
        "edge_kind": "CHANNEL_READ",
        "site_id": "site:00002000:00002010",
        "object_id": "obj:ram:20000100",
        "recognition": "heuristic",
        "source_associated": True,
        "traversable": True,
        "loaded_atom_id": "atom:read:00002010",
        "transfer_semantics": "MEMORY_CONTENT",
    }
    return {
        "schema_version": "ct-mini-channel-graph-v4",
        "strict_traversal_surface": "channel_edges",
        "source_associations": [
            {
                "association_id": "association:0001",
                "source_definition_id": "source-definition:0001",
                "source_id": "source:0001",
                "state_kind": "MEMORY_CONTENT",
                "function_id": "fn:00001000",
                "object_id": "obj:ram:20000100",
                "relation_kind": "CONCRETE_STORE",
                "site_id": "site:00001000:00001010",
                "precision": "EXACT",
                "channel_depth": 1,
            }
        ],
        "shared_objects": [
            {
                "node_id": "obj:ram:20000100",
                "node_kind": "SHARED_OBJECT",
                "object_id": "obj:ram:20000100",
                "base_object_id": "obj:ram:20000100",
                "transfer_semantics": "MEMORY_CONTENT",
                "source_lineage_ids": ["source-definition:0001"],
                "recognition": "heuristic",
                "writers": [
                    {
                        "edge_id": source_write["edge_id"],
                        "function_id": "fn:00001000",
                        "site_id": source_write["site_id"],
                        "stored_atom_id": source_write["stored_atom_id"],
                        "source_associated": True,
                    },
                    {
                        "edge_id": internal_write["edge_id"],
                        "function_id": "fn:00001000",
                        "site_id": internal_write["site_id"],
                        "stored_atom_id": internal_write["stored_atom_id"],
                        "source_associated": False,
                    },
                ],
                "readers": [
                    {
                        "edge_id": read_edge["edge_id"],
                        "function_id": "fn:00002000",
                        "site_id": read_edge["site_id"],
                        "loaded_atom_id": read_edge["loaded_atom_id"],
                    }
                ],
            }
        ],
        "function_nodes": [
            {"node_id": "fn:00001000", "node_kind": "FUNCTION"},
            {"node_id": "fn:00002000", "node_kind": "FUNCTION"},
            {"node_id": "fn:00003000", "node_kind": "FUNCTION"},
        ],
        "object_nodes": [
            {
                "node_id": "obj:ram:20000100",
                "object_id": "obj:ram:20000100",
                "legacy_identity_kind": "ABSOLUTE_SRAM",
            }
        ],
        "nodes": [
            {"node_id": "fn:00001000", "node_kind": "FUNCTION"},
            {"node_id": "fn:00002000", "node_kind": "FUNCTION"},
            {"node_id": "fn:00003000", "node_kind": "FUNCTION"},
            {
                "node_id": "obj:ram:20000100",
                "node_kind": "SHARED_OBJECT",
                "object_id": "obj:ram:20000100",
                "recognition": "heuristic",
            },
        ],
        "call_edges": [call_edge, callind_edge],
        "channel_edges": [source_write, internal_write, read_edge],
        "edges": [
            call_edge,
            callind_edge,
            source_write,
            internal_write,
            read_edge,
        ],
        "candidate_channel_edges": [],
        "channel_blockers": [],
        "value_object_bindings": [],
        "counts": {
            "function_nodes": 3,
            "shared_objects": 1,
            "call_edges": 2,
            "channel_edges": 3,
        },
    }


class ChannelGraphV4SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text())
        cls.validator = Draft202012Validator(cls.schema)

    def test_schema_is_valid_and_semantic_free_fixture_conforms(self) -> None:
        Draft202012Validator.check_schema(self.schema)
        self.validator.validate(semantic_free_artifact())

    def test_v3_surface_fields_remain_accepted_in_v4_envelope(self) -> None:
        artifact = semantic_free_artifact()
        artifact["dispatch_resolution"] = {
            "counts": {"resolved": 1},
            "applied_unique_targets": 1,
        }
        artifact["legacy_seed_metadata"] = {"schema_version": "legacy-test"}
        artifact["channel_edges"][0]["value_atom_id"] = "legacy:write-atom"
        artifact["channel_edges"][0]["paired_edge_ids"] = [
            artifact["channel_edges"][2]["edge_id"]
        ]
        artifact["shared_objects"][0]["writers"][0]["value_atom_id"] = (
            "legacy:write-atom"
        )
        self.validator.validate(artifact)

    def test_concrete_access_evidence_is_required(self) -> None:
        cases = []

        missing_writer_atom = semantic_free_artifact()
        del missing_writer_atom["shared_objects"][0]["writers"][0][
            "stored_atom_id"
        ]
        cases.append(missing_writer_atom)

        missing_reader_atom = semantic_free_artifact()
        del missing_reader_atom["shared_objects"][0]["readers"][0][
            "loaded_atom_id"
        ]
        cases.append(missing_reader_atom)

        missing_edge_atom = semantic_free_artifact()
        del missing_edge_atom["channel_edges"][0]["stored_atom_id"]
        cases.append(missing_edge_atom)

        for artifact in cases:
            with self.subTest():
                with self.assertRaises(ValidationError):
                    self.validator.validate(artifact)

    def test_relation_marks_and_directions_are_enforced(self) -> None:
        invalid_recognition = semantic_free_artifact()
        invalid_recognition["channel_edges"][0]["recognition"] = "unresolved"
        invalid_recognition["edges"][2]["recognition"] = "unresolved"

        invalid_source_mark = semantic_free_artifact()
        invalid_source_mark["channel_edges"][0]["source_associated"] = "yes"
        invalid_source_mark["edges"][2]["source_associated"] = "yes"

        reversed_write = semantic_free_artifact()
        reversed_write["channel_edges"][0]["src_node_id"] = "obj:ram:20000100"
        reversed_write["channel_edges"][0]["dst_node_id"] = "fn:00001000"
        reversed_write["edges"][2]["src_node_id"] = "obj:ram:20000100"
        reversed_write["edges"][2]["dst_node_id"] = "fn:00001000"

        for artifact in (
            invalid_recognition,
            invalid_source_mark,
            reversed_write,
        ):
            with self.subTest():
                with self.assertRaises(ValidationError):
                    self.validator.validate(artifact)


if __name__ == "__main__":
    unittest.main()
