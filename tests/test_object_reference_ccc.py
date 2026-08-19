from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import dataflow_objects  # noqa: E402
import object_reference_ccc as object_ccc  # noqa: E402


def node(
    value_id: str,
    *,
    slot: int | None = None,
    def_site: str = "",
    offset: int = 0,
    address: bool = False,
    pointer: bool = True,
) -> dict:
    return {
        "value_id": value_id,
        "object_id": f"param:test:{slot}" if slot is not None else value_id,
        "space": "ram" if address else "register",
        "offset": hex(offset),
        "size": 4,
        "high_data_type": "void *" if pointer else "uint32_t",
        "is_parameter": slot is not None,
        "is_input": slot is not None,
        "parameter_slot": slot,
        "index": slot,
        "is_constant": False,
        "is_address": address,
        "def_site_id": def_site,
    }


def constant(value: int) -> dict:
    return {
        "value_id": f"const:{value & 0xffffffff:x}:4",
        "object_id": f"const:{value & 0xffffffff:x}:4",
        "space": "const",
        "offset": hex(value & 0xFFFFFFFF),
        "size": 4,
        "high_data_type": "uint32_t",
        "is_parameter": False,
        "is_input": False,
        "parameter_slot": None,
        "is_constant": True,
        "is_address": False,
        "def_site_id": "",
    }


def op(
    site: str,
    mnemonic: str,
    inputs: list[dict],
    output: dict | None = None,
) -> dict:
    return {
        "site_id": site,
        "mnemonic": mnemonic,
        "inputs": inputs,
        "output": output,
    }


def call(
    site: str,
    target: str,
    actuals: list[dict],
    output: dict | None = None,
) -> dict:
    return {
        "site_id": site,
        "mnemonic": "CALL",
        "inputs": [constant(int(target.split(":")[-1], 16))] + actuals,
        "output": output,
        "call": {
            "target_function_id": target,
            "argument_value_ids": [item["value_id"] for item in actuals],
        },
    }


def body_functions(*, dynamic_insert_address: bool = False) -> list[dict]:
    insert_container = node("value:insert-container", slot=0)
    insert_payload = node("value:insert-payload", slot=1)
    payload_cast = node("value:payload-cast", def_site="insert:cast")
    insert_address = node("value:insert-address", def_site="insert:address")
    insert_address_inputs = [insert_container, constant(4)]
    if dynamic_insert_address:
        insert_address_inputs = [insert_container, node("value:index", slot=2)]

    remove_container = node("value:remove-container", slot=0)
    remove_address = node("value:remove-address", def_site="remove:address")
    loaded = node("value:loaded", def_site="remove:load")
    returned = node("value:returned", def_site="remove:copy")
    return [
        {
            "function_id": "fn:1000",
            "entry": "0x1000",
            "name": "implementation_a",
            "parameters": [insert_container, insert_payload],
            "pcode_ops": [
                op("insert:cast", "CAST", [insert_payload], payload_cast),
                op(
                    "insert:address",
                    "PTRSUB" if not dynamic_insert_address else "INT_ADD",
                    insert_address_inputs,
                    insert_address,
                ),
                op(
                    "insert:store",
                    "STORE",
                    [constant(0), insert_address, payload_cast],
                ),
            ],
        },
        {
            "function_id": "fn:2000",
            "entry": "0x2000",
            "name": "implementation_b",
            "parameters": [remove_container],
            "pcode_ops": [
                op(
                    "remove:address",
                    "PTRSUB",
                    [remove_container, constant(4)],
                    remove_address,
                ),
                op(
                    "remove:load",
                    "LOAD",
                    [constant(0), remove_address],
                    loaded,
                ),
                op("remove:copy", "COPY", [loaded], returned),
                op("remove:return", "RETURN", [constant(0), returned]),
            ],
        },
    ]


def fixture(*, source_associated: bool = True) -> tuple[dict, list[dict]]:
    functions = body_functions()
    queue = node("value:queue", offset=0x20000000, address=True)
    payload = node("value:payload", offset=0x20001000, address=True)
    queue_writer = node("value:writer-queue", def_site="writer:queue-offset")
    payload_alias = node("value:payload-alias", def_site="writer:payload-copy")
    queue_reader = node("value:reader-queue", def_site="reader:queue-offset")
    result = node("value:dequeued", def_site="writer:remove-call")
    functions.extend(
        [
            {
                "function_id": "fn:3000",
                "entry": "0x3000",
                "name": "producer_context",
                "parameters": [],
                "pcode_ops": [
                    op(
                        "writer:queue-offset",
                        "PTRADD",
                        [queue, constant(2), constant(4)],
                        queue_writer,
                    ),
                    op(
                        "writer:payload-copy",
                        "COPY",
                        [payload],
                        payload_alias,
                    ),
                    call(
                        "writer:insert-call",
                        "fn:1000",
                        [queue_writer, payload_alias],
                    ),
                ],
            },
            {
                "function_id": "fn:4000",
                "entry": "0x4000",
                "name": "consumer_context",
                "parameters": [],
                "pcode_ops": [
                    op(
                        "reader:queue-offset",
                        "PTRADD",
                        [queue, constant(2), constant(4)],
                        queue_reader,
                    ),
                    call(
                        "reader:remove-call",
                        "fn:2000",
                        [queue_reader],
                        result,
                    ),
                ],
            },
        ]
    )
    associations = []
    if source_associated:
        associations.append(
            {
                "association_id": "source-association:1",
                "source_definition_id": "source-definition:1",
                "source_id": "SO1",
                "state_kind": "OBJECT_REFERENCE",
                "function_id": "fn:3000",
                "atom_id": "value:payload",
                "object_id": "obj:symbol:20001000:payload",
                "pointee_object_id": "obj:symbol:20001000:payload",
                "recognition": "deterministic",
                "analysis_precision": "EXACT",
            }
        )
    return {"functions": functions}, associations


def runtime(facts: dict) -> dataflow_objects.RuntimeObjectIndex:
    def static_object(raw: dict):
        if not bool(raw.get("is_address")):
            return None
        address = int(str(raw.get("offset", "0")), 16)
        names = {0x20000000: "queue", 0x20001000: "payload", 0x20002000: "ctx"}
        if address not in names:
            return None
        object_id = f"obj:symbol:{address:x}:{names[address]}"
        return object_id, {"storage_kind": "STATIC_WRITABLE_DATA"}, "TEST"

    return dataflow_objects.RuntimeObjectIndex(
        facts,
        static_object=static_object,
        stack_descriptor=lambda raw, function_id: None,
        stack_object_id=lambda function_id, offset: f"obj:stack:{function_id}:{offset}",
    )


class ObjectReferenceCCCTests(unittest.TestCase):
    def test_recovers_body_insert_and_remove_without_names(self) -> None:
        facts = {"functions": body_functions()}
        summaries, blockers = object_ccc.recover_body_effect_summaries(facts)
        self.assertEqual(blockers, [])
        self.assertCountEqual(
            [
                (row["effect_kind"], row["container_relative_offset"])
                for row in summaries
            ],
            [("INSERT", 4), ("REMOVE", 4)],
        )
        insert = next(row for row in summaries if row["effect_kind"] == "INSERT")
        self.assertEqual(insert["container_parameter_slot"], 0)
        self.assertEqual(insert["payload_parameter_slot"], 1)
        self.assertEqual(insert["analysis_precision"], "EXACT")

    def test_recovers_role_preserving_insert_and_remove_wrappers(self) -> None:
        functions = body_functions()

        insert_container = node("value:wrapper-insert-container", slot=0)
        insert_unused = node(
            "value:wrapper-insert-unused", slot=1, pointer=False
        )
        insert_payload = node("value:wrapper-insert-payload", slot=2)
        adjusted_payload = node(
            "value:wrapper-adjusted-payload", def_site="wrapper-insert:adjust"
        )
        functions.append(
            {
                "function_id": "fn:5000",
                "entry": "0x5000",
                "name": "implementation_c",
                "parameters": [insert_container, insert_unused, insert_payload],
                "pcode_ops": [
                    op(
                        "wrapper-insert:adjust",
                        "INT_ADD",
                        [insert_payload, constant(-8)],
                        adjusted_payload,
                    ),
                    call(
                        "wrapper-insert:call",
                        "fn:1000",
                        [insert_container, adjusted_payload],
                    ),
                ],
            }
        )

        remove_container = node("value:wrapper-remove-container", slot=0)
        removed = node("value:wrapper-removed", def_site="wrapper-remove:call")
        adjusted_result = node(
            "value:wrapper-adjusted-result", def_site="wrapper-remove:adjust"
        )
        functions.append(
            {
                "function_id": "fn:6000",
                "entry": "0x6000",
                "name": "implementation_d",
                "parameters": [remove_container],
                "pcode_ops": [
                    call(
                        "wrapper-remove:call",
                        "fn:2000",
                        [remove_container],
                        removed,
                    ),
                    op(
                        "wrapper-remove:adjust",
                        "INT_ADD",
                        [removed, constant(8)],
                        adjusted_result,
                    ),
                    op(
                        "wrapper-remove:return",
                        "RETURN",
                        [constant(0), adjusted_result],
                    ),
                ],
            }
        )

        summaries, blockers = object_ccc.recover_body_effect_summaries(
            {"functions": functions}
        )
        self.assertNotIn(
            "object_reference_wrapper_summary_depth_budget_exhausted",
            {row.get("reason") for row in blockers},
        )
        insert = next(
            row
            for row in summaries
            if row.get("function_id") == "fn:5000"
            and row.get("proof")
            == "RESOLVED_CALL_FORMAL_BINDING_TO_INSERT_EFFECT"
        )
        self.assertEqual(insert["container_parameter_slot"], 0)
        self.assertEqual(insert["payload_parameter_slot"], 2)
        self.assertEqual(insert["container_relative_offset"], 4)
        self.assertEqual(insert["payload_relative_offset"], -8)

        remove = next(
            row
            for row in summaries
            if row.get("function_id") == "fn:6000"
            and row.get("proof")
            == "RESOLVED_CALL_RETURN_BINDING_TO_REMOVE_EFFECT"
        )
        self.assertEqual(remove["container_parameter_slot"], 0)
        self.assertEqual(remove["container_relative_offset"], 4)
        self.assertEqual(remove["return_adjustment"], 8)
        self.assertEqual(remove["analysis_precision"], "EXACT")

    def test_instantiates_source_writer_and_matching_reader(self) -> None:
        facts, associations = fixture()
        result = object_ccc.recover_object_reference_ccc(
            facts,
            source_associations=associations,
            runtime=runtime(facts),
        )
        self.assertEqual(result["metrics"]["writer_facts"], 1)
        self.assertEqual(result["metrics"]["reader_facts"], 1)
        writer = result["writer_facts"][0]
        reader = result["reader_facts"][0]
        # Callsite actual contributes +8 and the body Region contributes +4.
        self.assertEqual(writer["region"]["offset"], 12)
        self.assertEqual(writer["region"]["base_object_id"], "obj:symbol:20000000:queue")
        self.assertEqual(writer["source_definition_ids"], ["source-definition:1"])
        self.assertTrue(writer["ccc_eligible"])
        self.assertTrue(reader["ccc_eligible"])
        self.assertEqual(reader["source_ids"], ["SO1"])
        self.assertEqual(writer["recognition"], "deterministic")
        self.assertEqual(reader["analysis_precision"], "EXACT")

    def test_unassociated_payload_is_a_blocker_not_a_writer(self) -> None:
        facts, associations = fixture(source_associated=False)
        result = object_ccc.recover_object_reference_ccc(
            facts,
            source_associations=associations,
            runtime=runtime(facts),
        )
        self.assertEqual(result["writer_facts"], [])
        self.assertIn(
            "object_reference_payload_not_source_associated",
            {row["reason"] for row in result["blockers"]},
        )
        self.assertFalse(result["reader_facts"][0]["ccc_eligible"])

    def test_dynamic_container_address_does_not_form_body_summary(self) -> None:
        facts = {"functions": body_functions(dynamic_insert_address=True)}
        summaries, blockers = object_ccc.recover_body_effect_summaries(facts)
        self.assertEqual(
            [row["effect_kind"] for row in summaries],
            ["REMOVE"],
        )
        self.assertIn(
            "object_reference_insert_container_region_unresolved",
            {row["reason"] for row in blockers},
        )

    def test_loaded_pointer_field_has_stable_pointee_identity(self) -> None:
        functions = body_functions()
        ctx = node("value:ctx", offset=0x20002000, address=True)

        def indirect_caller(function_id: str, call_site: str, target: str, payload: bool):
            field_address = node(f"value:{function_id}:field", def_site=f"{call_site}:field")
            loaded_container = node(
                f"value:{function_id}:container", def_site=f"{call_site}:load"
            )
            ops = [
                op(
                    f"{call_site}:field",
                    "PTRSUB",
                    [ctx, constant(4)],
                    field_address,
                ),
                op(
                    f"{call_site}:load",
                    "LOAD",
                    [constant(0), field_address],
                    loaded_container,
                ),
            ]
            if payload:
                source_payload = node(
                    "value:indirect-payload", offset=0x20001000, address=True
                )
                ops.append(call(call_site, target, [loaded_container, source_payload]))
            else:
                ops.append(
                    call(
                        call_site,
                        target,
                        [loaded_container],
                        node("value:indirect-result", def_site=call_site),
                    )
                )
            return {
                "function_id": function_id,
                "entry": "0x5000" if payload else "0x6000",
                "name": "arbitrary_context",
                "parameters": [],
                "pcode_ops": ops,
            }

        functions.extend(
            [
                indirect_caller("fn:5000", "indirect:write", "fn:1000", True),
                indirect_caller("fn:6000", "indirect:read", "fn:2000", False),
            ]
        )
        facts = {"functions": functions}
        associations = [
            {
                "association_id": "source-association:indirect",
                "source_definition_id": "source-definition:indirect",
                "source_id": "SO2",
                "state_kind": "OBJECT_REFERENCE",
                "function_id": "fn:5000",
                "atom_id": "value:indirect-payload",
                "recognition": "deterministic",
                "analysis_precision": "EXACT",
            }
        ]
        result = object_ccc.recover_object_reference_ccc(
            facts,
            source_associations=associations,
            runtime=runtime(facts),
        )
        eligible_writers = [row for row in result["writer_facts"] if row["ccc_eligible"]]
        eligible_readers = [row for row in result["reader_facts"] if row["ccc_eligible"]]
        self.assertEqual(len(eligible_writers), 1)
        self.assertEqual(len(eligible_readers), 1)
        self.assertTrue(
            eligible_writers[0]["region"]["base_object_id"].startswith(
                "obj:access-path:"
            )
        )
        self.assertEqual(
            eligible_writers[0]["region"]["base_object_id"],
            eligible_readers[0]["region"]["base_object_id"],
        )
        # Parent-field +4 is before dereference; pointee Region starts at +4.
        self.assertEqual(eligible_writers[0]["region"]["offset"], 4)

    def test_heuristic_source_precision_is_preserved(self) -> None:
        facts, associations = fixture()
        associations[0]["recognition"] = "heuristic"
        associations[0]["analysis_precision"] = "MAY"
        result = object_ccc.recover_object_reference_ccc(
            facts,
            source_associations=associations,
            runtime=runtime(facts),
        )
        self.assertEqual(result["writer_facts"][0]["recognition"], "heuristic")
        self.assertEqual(result["writer_facts"][0]["analysis_precision"], "MAY")
        self.assertEqual(result["reader_facts"][0]["analysis_precision"], "MAY")

    def test_value_source_association_is_admitted_by_exact_atom_lineage(self) -> None:
        facts, associations = fixture()
        associations[0]["state_kind"] = "VALUE"
        associations[0]["object_id"] = ""
        associations[0]["pointee_object_id"] = ""
        result = object_ccc.recover_object_reference_ccc(
            facts,
            source_associations=associations,
            runtime=runtime(facts),
        )
        self.assertEqual(len(result["writer_facts"]), 1)
        self.assertEqual(result["writer_facts"][0]["source_state_kinds"], ["VALUE"])
        self.assertTrue(result["writer_facts"][0]["ccc_eligible"])


if __name__ == "__main__":
    unittest.main()
