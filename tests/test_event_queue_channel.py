from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import ccc_effect_resolver as ccc  # noqa: E402
import dataflow_objects  # noqa: E402
import shared_object_miner  # noqa: E402


def node(
    value_id: str,
    *,
    slot: int | None = None,
    def_site: str = "",
    offset: int = 0,
    address: bool = False,
) -> dict:
    return {
        "value_id": value_id,
        "object_id": f"param:{slot}" if slot is not None else value_id,
        "space": "ram" if address else "register",
        "offset": hex(offset),
        "size": 4,
        "high_data_type": "void *",
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
        "value_id": f"const:{value:x}:4",
        "object_id": f"const:{value:x}:4",
        "space": "const",
        "offset": hex(value),
        "size": 4,
        "high_data_type": "void *",
        "is_parameter": False,
        "is_input": False,
        "parameter_slot": None,
        "is_constant": True,
        "is_address": False,
        "def_site_id": "",
    }


def call(site: str, target: str, actuals: list[dict]) -> dict:
    return {
        "site_id": site,
        "mnemonic": "CALL",
        "inputs": [constant(int(target.split(":")[-1], 16))] + actuals,
        "output": None,
        "call": {
            "target_function_id": target,
            "argument_value_ids": [item["value_id"] for item in actuals],
        },
    }


def fixture() -> tuple[dict, list[dict]]:
    receiver = node("value:receiver", slot=0)
    event = node("value:event", slot=1)
    payload = node("value:payload", slot=2)
    queue_address = node("value:queue-address", offset=0x20000300, address=True)
    loaded_event = node("value:loaded-event", def_site="site:load-event")
    loaded_payload = node("value:loaded-payload", def_site="site:load-payload")
    loaded_receiver = node("value:loaded-receiver", def_site="site:load-receiver")
    dispatch_receiver = node("value:dispatch-receiver", slot=0)
    dispatch_event = node("value:dispatch-event", slot=1)
    dispatch_payload = node("value:dispatch-payload", slot=2)
    callback_address = node("value:callback-address", def_site="site:callback-address")
    callback_target = node("value:callback-target", def_site="site:load-callback")
    handler_payload = node("value:handler-payload", slot=2)
    caller_receiver = node("value:caller-receiver", offset=0x20000100, address=True)
    caller_payload = node("value:caller-payload", offset=0x20000200, address=True)

    facts = {
        "memory_blocks": [
            {
                "name": ".text",
                "start": "0x1000",
                "end": "0x5fff",
                "execute": True,
                "write": False,
            }
        ],
        "functions": [
            {
                "function_id": "fn:1000",
                "entry": "0x1000",
                "name": "f_a",
                "parameters": [receiver, event, payload],
                "pcode_ops": [
                    {
                        "site_id": "site:store-receiver",
                        "mnemonic": "STORE",
                        "inputs": [constant(0), queue_address, receiver],
                    },
                    {
                        "site_id": "site:store-event",
                        "mnemonic": "STORE",
                        "inputs": [constant(0), queue_address, event],
                    },
                    {
                        "site_id": "site:store-payload",
                        "mnemonic": "STORE",
                        "inputs": [constant(0), queue_address, payload],
                    },
                ],
            },
            {
                "function_id": "fn:2000",
                "entry": "0x2000",
                "name": "f_b",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:load-event",
                        "mnemonic": "LOAD",
                        "output": loaded_event,
                        "inputs": [constant(0), queue_address],
                    },
                    {
                        "site_id": "site:load-payload",
                        "mnemonic": "LOAD",
                        "output": loaded_payload,
                        "inputs": [constant(0), queue_address],
                    },
                    {
                        "site_id": "site:load-receiver",
                        "mnemonic": "LOAD",
                        "output": loaded_receiver,
                        "inputs": [constant(0), queue_address],
                    },
                    call(
                        "site:dispatch",
                        "fn:3000",
                        [loaded_receiver, loaded_event, loaded_payload],
                    ),
                ],
            },
            {
                "function_id": "fn:3000",
                "entry": "0x3000",
                "name": "f_c",
                "parameters": [
                    dispatch_receiver,
                    dispatch_event,
                    dispatch_payload,
                ],
                "pcode_ops": [
                    {
                        "site_id": "site:callback-address",
                        "mnemonic": "PTRSUB",
                        "output": callback_address,
                        "inputs": [dispatch_receiver, constant(8)],
                    },
                    {
                        "site_id": "site:load-callback",
                        "mnemonic": "LOAD",
                        "output": callback_target,
                        "inputs": [constant(0), callback_address],
                    },
                    {
                        "site_id": "site:callind",
                        "mnemonic": "CALLIND",
                        "inputs": [
                            callback_target,
                            dispatch_receiver,
                            dispatch_event,
                            dispatch_payload,
                        ],
                        "output": None,
                        "call": {
                            "target_function_id": "",
                            "argument_value_ids": [
                                dispatch_receiver["value_id"],
                                dispatch_event["value_id"],
                                dispatch_payload["value_id"],
                            ],
                        },
                    },
                ],
            },
            {
                "function_id": "fn:5000",
                "entry": "0x5000",
                "name": "f_d",
                "parameters": [
                    node("value:handler-receiver", slot=0),
                    node("value:handler-event", slot=1),
                    handler_payload,
                ],
                "pcode_ops": [],
            },
            {
                "function_id": "fn:6000",
                "entry": "0x6000",
                "name": "f_e",
                "parameters": [],
                "pcode_ops": [
                    call(
                        "site:enqueue",
                        "fn:1000",
                        [caller_receiver, constant(7), caller_payload],
                    )
                ],
            },
        ],
    }
    exact = [
        {
            "function_id": "fn:1000",
            "object_id": "obj:queue",
            "edge_kind": "OBJECT_WRITE",
            "site_id": "site:store-receiver",
            "region_offset": 8,
            "region_extent": 4,
        },
        {
            "function_id": "fn:1000",
            "object_id": "obj:queue",
            "edge_kind": "OBJECT_WRITE",
            "site_id": "site:store-event",
            "region_offset": 0,
            "region_extent": 1,
        },
        {
            "function_id": "fn:1000",
            "object_id": "obj:queue",
            "edge_kind": "OBJECT_WRITE",
            "site_id": "site:store-payload",
            "region_offset": 4,
            "region_extent": 4,
        },
        {
            "function_id": "fn:2000",
            "object_id": "obj:queue",
            "edge_kind": "OBJECT_READ",
            "site_id": "site:load-event",
            "region_offset": 0,
            "region_extent": 1,
        },
        {
            "function_id": "fn:2000",
            "object_id": "obj:queue",
            "edge_kind": "OBJECT_READ",
            "site_id": "site:load-payload",
            "region_offset": 4,
            "region_extent": 4,
        },
        {
            "function_id": "fn:2000",
            "object_id": "obj:queue",
            "edge_kind": "OBJECT_READ",
            "site_id": "site:load-receiver",
            "region_offset": 8,
            "region_extent": 4,
        },
    ]
    return facts, exact


class EventQueueChannelTests(unittest.TestCase):
    def runtime(self, facts: dict) -> dataflow_objects.RuntimeObjectIndex:
        def static_object(raw: dict):
            address = int(str(raw.get("offset", "0")), 16)
            names = {
                0x20000100: "receiver",
                0x20000200: "payload",
                0x20000300: "queue",
            }
            if address not in names or not bool(raw.get("is_address")):
                return None
            object_id = f"obj:symbol:{address:x}:{names[address]}"
            return object_id, {"storage_kind": "STATIC_WRITABLE_DATA"}, "TEST"

        return dataflow_objects.RuntimeObjectIndex(
            facts,
            static_object=static_object,
            stack_descriptor=lambda raw, function_id: None,
            stack_object_id=lambda function_id, offset: f"obj:stack:{function_id}:{offset}",
        )

    def test_record_contract_builds_source_associated_channel(self) -> None:
        facts, exact = fixture()
        candidates, blockers = ccc.build_event_queue_candidates(
            facts,
            runtime=self.runtime(facts),
            literal_words={0x20000108: 0x5001},
            exact_access_edges=exact,
            source_associations=[
                {
                    "association_id": "association:1",
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                    "state_kind": "OBJECT_REFERENCE",
                    "function_id": "fn:6000",
                    "atom_id": "value:caller-payload",
                    "object_id": "obj:symbol:20000200:payload",
                    "pointee_object_id": "obj:symbol:20000200:payload",
                }
            ],
        )
        self.assertEqual(blockers, [])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["transfer_semantics"], "OBJECT_REFERENCE")
        self.assertEqual(candidates[0]["readers"][0]["function_id"], "fn:5000")
        admitted = shared_object_miner.mine_shared_objects(candidates)
        edges = shared_object_miner.materialize_channel_edges(
            admitted["shared_objects"]
        )
        self.assertEqual(
            {edge["edge_kind"] for edge in edges},
            {"CHANNEL_WRITE", "CHANNEL_READ"},
        )

    def test_unknown_receiver_target_does_not_create_channel(self) -> None:
        facts, exact = fixture()
        candidates, blockers = ccc.build_event_queue_candidates(
            facts,
            runtime=self.runtime(facts),
            literal_words={},
            exact_access_edges=exact,
            source_associations=[
                {
                    "association_id": "association:1",
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                    "state_kind": "OBJECT_REFERENCE",
                    "function_id": "fn:6000",
                    "atom_id": "value:caller-payload",
                    "object_id": "obj:symbol:20000200:payload",
                }
            ],
        )
        self.assertEqual(candidates, [])
        self.assertIn(
            "event_receiver_callback_target_unresolved",
            {row["reason"] for row in blockers},
        )


if __name__ == "__main__":
    unittest.main()
