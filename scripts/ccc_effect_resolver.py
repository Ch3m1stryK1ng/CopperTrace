#!/usr/bin/env python3
"""Recover payload-preserving deferred callback channels from High P-code."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

import dataflow_objects
import source_association


def parse_address(value: Any) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def executable_targets(program_facts: dict[str, Any]) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    for function in list(program_facts.get("functions", []) or []):
        address = parse_address(function.get("entry"))
        if address is None:
            function_id = str(function.get("function_id", ""))
            if function_id.startswith("fn:"):
                address = parse_address(function_id[3:])
        if address is not None:
            out[address & ~1] = function
    return out


def resolve_function_pointer(
    node: dict[str, Any],
    *,
    targets: dict[int, dict[str, Any]],
    literal_words: dict[int, int],
    ops_by_site: dict[str, dict[str, Any]],
    depth: int = 0,
    seen: set[str] | None = None,
) -> tuple[dict[str, Any], list[str]] | None:
    if depth > 12:
        return None
    seen = set(seen or set())
    atom = dataflow_objects.identity(node)
    if atom and atom in seen:
        return None
    if atom:
        seen.add(atom)

    raw = parse_address(node.get("offset"))
    candidates: list[tuple[int, str]] = []
    if raw is not None:
        candidates.append((raw, "DIRECT_VALUE"))
        if raw in literal_words:
            candidates.append((literal_words[raw], "INITIALIZED_LITERAL"))
        aligned = raw & ~3
        if aligned in literal_words:
            candidates.append((literal_words[aligned], "INITIALIZED_ALIGNED_LITERAL"))
    resolved = {
        address & ~1: (targets[address & ~1], provenance)
        for address, provenance in candidates
        if (address & ~1) in targets
    }
    if len(resolved) == 1:
        function, provenance = next(iter(resolved.values()))
        return function, [provenance]

    op = ops_by_site.get(str(node.get("def_site_id", "")))
    if not op:
        return None
    mnemonic = str(op.get("mnemonic", ""))
    if mnemonic not in {
        "COPY",
        "CAST",
        "INDIRECT",
        "LOAD",
        "MULTIEQUAL",
        "PTRSUB",
        "PTRADD",
        "INT_ADD",
    }:
        return None
    nested = []
    for item in list(op.get("inputs", []) or []):
        item = dict(item or {})
        if bool(item.get("is_constant")) and mnemonic not in {
            "LOAD",
            "PTRSUB",
            "PTRADD",
            "INT_ADD",
        }:
            continue
        candidate = resolve_function_pointer(
            item,
            targets=targets,
            literal_words=literal_words,
            ops_by_site=ops_by_site,
            depth=depth + 1,
            seen=seen,
        )
        if candidate:
            nested.append(candidate)
    ids = {str(row[0].get("function_id", "")) for row in nested}
    if len(ids) == 1:
        function = nested[0][0]
        evidence = [str(op.get("site_id", ""))]
        for _, path in nested:
            evidence.extend(path)
        return function, evidence
    return None


def _call_actuals(op: dict[str, Any]) -> list[dict[str, Any]]:
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    return inputs[1:] if inputs else []


def _parameter_slot_from_root(root: str, function_id: str) -> int | None:
    prefix = f"obj:formal:{function_id}:"
    if not root.startswith(prefix):
        return None
    try:
        return int(root[len(prefix) :])
    except ValueError:
        return None


def _payload_forwarding_chain(
    function_id: str,
    payload_slot: int,
    *,
    functions: dict[str, dict[str, Any]],
    runtime: dataflow_objects.RuntimeObjectIndex,
    max_depth: int,
    depth: int = 0,
    seen: set[tuple[str, int]] | None = None,
    min_op_position: int = -1,
) -> list[dict[str, Any]]:
    """Return a unique direct-call chain that preserves one pointer payload."""

    if depth > max_depth:
        return []
    seen = set(seen or set())
    key = (function_id, payload_slot)
    if key in seen:
        return []
    seen.add(key)
    function = functions.get(function_id, {})
    expected_root = f"obj:formal:{function_id}:{payload_slot}"
    candidates: list[tuple[dict[str, Any], int]] = []
    for op_position, op in enumerate(list(function.get("pcode_ops", []) or [])):
        if op_position <= min_op_position:
            continue
        if str(op.get("mnemonic", "")) != "CALL":
            continue
        target_id = str(dict(op.get("call", {}) or {}).get("target_function_id", ""))
        if target_id not in functions:
            continue
        for index, actual in enumerate(_call_actuals(op)):
            binding = runtime.resolve(actual, function_id)
            if binding and str(binding.get("root_object_id", "")) == expected_root:
                candidates.append((op, index))
    # Multiple forwarding calls are not a unique deferred-channel contract.
    if len(candidates) != 1:
        return []
    op, actual_index = candidates[0]
    target_id = str(dict(op.get("call", {}) or {}).get("target_function_id", ""))
    row = {
        "function_id": function_id,
        "site_id": str(op.get("site_id", "")),
        "target_function_id": target_id,
        "payload_actual_index": actual_index,
        "payload_atom_id": dataflow_objects.identity(_call_actuals(op)[actual_index]),
    }
    nested = _payload_forwarding_chain(
        target_id,
        actual_index,
        functions=functions,
        runtime=runtime,
        max_depth=max_depth,
        depth=depth + 1,
        seen=seen,
        min_op_position=-1,
    )
    return [row] + nested


def _field_offsets(path: list[str] | tuple[str, ...]) -> tuple[int, ...]:
    offsets: list[int] = []
    for item in path:
        text = str(item)
        if not text.startswith("byte_offset:"):
            continue
        try:
            value = int(text.split(":", 1)[1], 0)
        except ValueError:
            continue
        if value:
            offsets.append(value)
    return tuple(offsets)


def callback_dispatch_consumers(
    functions: dict[str, dict[str, Any]],
    runtime: dataflow_objects.RuntimeObjectIndex,
) -> list[dict[str, Any]]:
    """Find dequeue-result objects whose stored callback field is invoked.

    This is intentionally structural.  A consumer must obtain an object from
    a direct call using a formal queue-like input, load a function pointer from
    that returned object, and execute a CALLIND through the loaded field.  It
    does not rely on queue, work, handler, or framework function names.
    """

    consumers: list[dict[str, Any]] = []
    for function_id, function in functions.items():
        calls_by_site = {
            str(op.get("site_id", "")): op
            for op in list(function.get("pcode_ops", []) or [])
            if str(op.get("mnemonic", "")) == "CALL"
        }
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALLIND":
                continue
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            if not inputs:
                continue
            target_binding = runtime.resolve(inputs[0], function_id)
            if not target_binding:
                continue
            root = str(target_binding.get("root_object_id", ""))
            prefix = "obj:call-result:"
            if not root.startswith(prefix):
                continue
            dequeue_site = root[len(prefix) :]
            dequeue_call = calls_by_site.get(dequeue_site)
            if not dequeue_call:
                continue
            queue_slots: set[int] = set()
            for actual in _call_actuals(dequeue_call):
                binding = runtime.resolve(actual, function_id)
                if not binding:
                    continue
                slot = _parameter_slot_from_root(
                    str(binding.get("root_object_id", "")), function_id
                )
                if slot is not None:
                    queue_slots.add(slot)
            if len(queue_slots) != 1:
                continue
            dequeue_target_id = str(
                dict(dequeue_call.get("call", {}) or {}).get(
                    "target_function_id", ""
                )
            )
            dequeue_target = functions.get(dequeue_target_id, {})
            dequeue_parameters = list(dequeue_target.get("parameters", []) or [])
            if not dequeue_target or not dequeue_parameters:
                continue
            dequeue_queue_root = f"obj:formal:{dequeue_target_id}:0"
            queue_memory_sites: list[str] = []
            pointer_return_sites: list[str] = []
            for target_op in list(dequeue_target.get("pcode_ops", []) or []):
                mnemonic = str(target_op.get("mnemonic", ""))
                target_inputs = [
                    dict(item or {})
                    for item in list(target_op.get("inputs", []) or [])
                ]
                if mnemonic in {"LOAD", "STORE"} and target_inputs:
                    address = target_inputs[-2] if mnemonic == "STORE" else target_inputs[-1]
                    address_binding = runtime.resolve(address, dequeue_target_id)
                    if address_binding and str(
                        address_binding.get("root_object_id", "")
                    ) == dequeue_queue_root:
                        queue_memory_sites.append(str(target_op.get("site_id", "")))
                if mnemonic == "RETURN":
                    for value in target_inputs[1:]:
                        if dataflow_objects.is_pointer(value) and not bool(
                            value.get("is_constant")
                        ):
                            pointer_return_sites.append(
                                str(target_op.get("site_id", ""))
                            )
            if not queue_memory_sites or not pointer_return_sites:
                continue
            offsets = _field_offsets(target_binding.get("access_path", []) or [])
            if not offsets:
                continue
            consumers.append(
                {
                    "function_id": function_id,
                    "dequeue_site_id": dequeue_site,
                    "dequeue_target_function_id": str(
                        dict(dequeue_call.get("call", {}) or {}).get(
                            "target_function_id", ""
                        )
                    ),
                    "dequeue_queue_memory_sites": sorted(set(queue_memory_sites)),
                    "dequeue_pointer_return_sites": sorted(set(pointer_return_sites)),
                    "queue_parameter_slot": next(iter(queue_slots)),
                    "callback_call_site_id": str(op.get("site_id", "")),
                    "callback_field_offsets": list(offsets),
                    "callback_target_access_path": list(
                        target_binding.get("access_path", []) or []
                    ),
                }
            )
    return consumers


def terminal_enqueue_contract(
    chain: list[dict[str, Any]],
    *,
    initial_payload_slot: int,
    functions: dict[str, dict[str, Any]],
    runtime: dataflow_objects.RuntimeObjectIndex,
) -> dict[str, Any] | None:
    """Find the unique chain call that forwards queue and payload together."""

    if not chain:
        return None
    candidates: list[dict[str, Any]] = []
    for chain_index, row in enumerate(chain):
        caller_id = str(row.get("function_id", ""))
        caller = functions.get(caller_id, {})
        payload_slot = (
            initial_payload_slot
            if chain_index == 0
            else int(chain[chain_index - 1].get("payload_actual_index", -1))
        )
        if not caller or payload_slot < 0:
            continue
        payload_root = f"obj:formal:{caller_id}:{payload_slot}"
        op = next(
            (
                candidate
                for candidate in list(caller.get("pcode_ops", []) or [])
                if str(candidate.get("site_id", ""))
                == str(row.get("site_id", ""))
                and str(candidate.get("mnemonic", "")) == "CALL"
            ),
            None,
        )
        if op is None:
            continue
        payload_actuals: list[int] = []
        other_formal_slots: set[int] = set()
        for actual_index, actual in enumerate(_call_actuals(op)):
            binding = runtime.resolve(actual, caller_id)
            if not binding:
                continue
            root = str(binding.get("root_object_id", ""))
            if root == payload_root:
                payload_actuals.append(actual_index)
                continue
            slot = _parameter_slot_from_root(root, caller_id)
            if slot is not None and slot != payload_slot:
                other_formal_slots.add(slot)
        if payload_actuals and other_formal_slots:
            candidates.append(
                {
                    "terminal_function_id": caller_id,
                    "terminal_call_site_id": str(op.get("site_id", "")),
                    "mutator_target_function_id": str(
                        dict(op.get("call", {}) or {}).get(
                            "target_function_id", ""
                        )
                    ),
                    "payload_parameter_slot": payload_slot,
                    "payload_actual_indices": payload_actuals,
                    "queue_parameter_slots": sorted(other_formal_slots),
                }
            )
    return candidates[0] if len(candidates) == 1 else None


def build_deferred_callback_channels(
    program_facts: dict[str, Any],
    *,
    runtime: dataflow_objects.RuntimeObjectIndex,
    literal_words: dict[int, int],
    max_wrapper_depth: int = 2,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    functions = runtime.functions
    targets = executable_targets(program_facts)
    ops_by_site = {site: op for site, (_, op) in runtime.ops_by_site.items()}
    object_nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    dispatch_consumers = callback_dispatch_consumers(functions, runtime)

    def formal_atom(function_row: dict[str, Any], slot: int, fallback: dict[str, Any]) -> str:
        candidates: set[str] = set()
        for candidate_op in list(function_row.get("pcode_ops", []) or []):
            nodes = list(candidate_op.get("inputs", []) or [])
            if isinstance(candidate_op.get("output"), dict):
                nodes.append(candidate_op["output"])
            for node in nodes:
                node = dict(node or {})
                if (
                    node.get("parameter_slot") == slot
                    and bool(node.get("is_input"))
                    and str(node.get("value_id", ""))
                ):
                    candidates.add(str(node["value_id"]))
        if len(candidates) == 1:
            return next(iter(candidates))
        return dataflow_objects.identity(fallback)

    for function_id, function in functions.items():
        stores: list[dict[str, Any]] = []
        for op_position, op in enumerate(list(function.get("pcode_ops", []) or [])):
            if str(op.get("mnemonic", "")) != "STORE":
                continue
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            if len(inputs) < 2:
                continue
            address, stored = inputs[-2], inputs[-1]
            target = resolve_function_pointer(
                stored,
                targets=targets,
                literal_words=literal_words,
                ops_by_site=ops_by_site,
            )
            address_binding = runtime.resolve(address, function_id)
            if not target or not address_binding:
                continue
            payload_slot = _parameter_slot_from_root(
                str(address_binding.get("root_object_id", "")), function_id
            )
            if payload_slot is None:
                continue
            stores.append(
                {
                    "op_position": op_position,
                    "site_id": str(op.get("site_id", "")),
                    "payload_slot": payload_slot,
                    "handler": target[0],
                    "handler_evidence": target[1],
                    "handler_access_path": list(
                        address_binding.get("access_path", []) or []
                    ),
                }
            )

        for store in stores:
            stored_offsets = _field_offsets(store["handler_access_path"])
            matching_consumers = [
                row
                for row in dispatch_consumers
                if tuple(row.get("callback_field_offsets", []) or [])
                == stored_offsets
            ]
            if not stored_offsets or not matching_consumers:
                blockers.append(
                    {
                        "reason": "callback_store_has_no_matching_dequeue_dispatch",
                        "function_id": function_id,
                        "site_id": str(store["site_id"]),
                        "handler_field_offsets": list(stored_offsets),
                    }
                )
                continue
            chain = _payload_forwarding_chain(
                function_id,
                int(store["payload_slot"]),
                functions=functions,
                runtime=runtime,
                max_depth=max_wrapper_depth,
                min_op_position=int(store["op_position"]),
            )
            chain = [
                row
                for row in chain
                if next(
                    (
                        index
                        for index, op in enumerate(
                            list(function.get("pcode_ops", []) or [])
                        )
                        if str(op.get("site_id", "")) == str(row.get("site_id", ""))
                    ),
                    int(store["op_position"]) + 1,
                )
                > int(store["op_position"])
                or str(row.get("function_id", "")) != function_id
            ]
            if not chain:
                blockers.append(
                    {
                        "reason": "callback_store_has_no_unique_payload_submission",
                        "function_id": function_id,
                        "site_id": str(store["site_id"]),
                    }
                )
                continue
            enqueue_contract = terminal_enqueue_contract(
                chain,
                initial_payload_slot=int(store["payload_slot"]),
                functions=functions,
                runtime=runtime,
            )
            if enqueue_contract is None:
                blockers.append(
                    {
                        "reason": "submission_terminal_has_no_unique_queue_payload_contract",
                        "function_id": function_id,
                        "site_id": str(store["site_id"]),
                    }
                )
                continue
            terminal = chain[-1]
            handler = dict(store["handler"])
            handler_id = str(handler.get("function_id", ""))
            handler_parameters = sorted(
                list(handler.get("parameters", []) or []),
                key=lambda row: int(dict(row or {}).get("index", 0)),
            )
            if not handler_id or not handler_parameters:
                blockers.append(
                    {
                        "reason": "callback_target_has_no_payload_formal",
                        "function_id": function_id,
                        "site_id": str(store["site_id"]),
                    }
                )
                continue
            handler_formal = dict(handler_parameters[0] or {})
            handler_atom = formal_atom(handler, 0, handler_formal)
            writer_parameter = next(
                (
                    dict(parameter or {})
                    for parameter in list(function.get("parameters", []) or [])
                    if int(
                        dict(parameter or {}).get(
                            "parameter_slot",
                            dict(parameter or {}).get("index", -1),
                        )
                    )
                    == int(store["payload_slot"])
                ),
                {},
            )
            writer_atom = formal_atom(
                function,
                int(store["payload_slot"]),
                writer_parameter,
            )
            if not writer_atom or not handler_atom:
                continue
            token = hashlib.sha256(
                (
                    str(terminal.get("site_id", ""))
                    + "|"
                    + handler_id
                    + "|"
                    + str(store["payload_slot"])
                ).encode()
            ).hexdigest()[:20]
            object_id = f"obj:deferred-channel:{token}"
            object_nodes.append(
                {
                    "node_id": object_id,
                    "object_id": object_id,
                    "base_object_id": object_id,
                    "name": "",
                    "identity_kind": "DEFERRED_CALLBACK_CHANNEL",
                    "storage_kind": "SYNTHETIC_CHANNEL",
                    "writable": True,
                    "is_stack": False,
                    "is_rom": False,
                    "strict_region_eligible": False,
                    "shared_object": True,
                    "shared_object_candidate": True,
                    "shared_classification": "PAYLOAD_PRESERVING_DEFERRED_CALLBACK",
                    "shared_evidence_level": "STRUCTURAL_MAY_DATAFLOW",
                    "shared_limitations": [
                        "scheduler_timing_not_proved",
                        "single_runtime_queue_instance_not_proved",
                    ],
                    "source_evidence_ids": [],
                }
            )
            common = {
                "object_id": object_id,
                "base_object_id": object_id,
                "region": {
                    "object_id": object_id,
                    "base_object_id": object_id,
                    "offset": 0,
                    "extent": 1,
                    "size": 1,
                    "extent_kind": "PAYLOAD_OBJECT",
                },
                "analysis_precision": "MAY",
                "strict_admissible": True,
                "deterministic": False,
                "candidate_only": False,
                "traversable": True,
                "evidence_level": "BODY_PROVED_DEFERRED_CALLBACK_CONTRACT",
                "evidence": {
                    "callback_store_site_id": str(store["site_id"]),
                    "handler_function_id": handler_id,
                    "handler_resolution_evidence": list(
                        store["handler_evidence"]
                    ),
                    "handler_access_path": list(store["handler_access_path"]),
                    "dequeue_dispatch_consumers": matching_consumers,
                    "enqueue_contract": enqueue_contract,
                    "submission_chain": chain,
                },
            }
            write_id = f"deferred-channel-write:{token}"
            read_id = f"deferred-channel-read:{token}"
            edges.extend(
                [
                    {
                        **common,
                        "edge_id": write_id,
                        "edge_kind": "CHANNEL_WRITE",
                        "src_node_id": function_id,
                        "dst_node_id": object_id,
                        "function_id": function_id,
                        "site_id": str(chain[0].get("site_id", "")),
                        "value_atom_id": writer_atom,
                        "value_id": str(writer_parameter.get("value_id", "")),
                        "value_object_id": str(writer_parameter.get("object_id", "")),
                        "paired_edge_ids": [read_id],
                    },
                    {
                        **common,
                        "edge_id": read_id,
                        "edge_kind": "CHANNEL_READ",
                        "src_node_id": object_id,
                        "dst_node_id": handler_id,
                        "function_id": handler_id,
                        "site_id": str(store["site_id"]),
                        "value_atom_id": handler_atom,
                        "value_id": str(handler_formal.get("value_id", "")),
                        "value_object_id": str(handler_formal.get("object_id", "")),
                        "paired_edge_ids": [write_id],
                    },
                ]
            )

    unique_nodes = {str(node["object_id"]): node for node in object_nodes}
    unique_edges = {str(edge["edge_id"]): edge for edge in edges}
    return (
        [unique_nodes[key] for key in sorted(unique_nodes)],
        [unique_edges[key] for key in sorted(unique_edges)],
        blockers,
    )


_LOCAL_POINTER_TRANSFERS = {
    "COPY",
    "CAST",
    "INDIRECT",
    "INT_ZEXT",
    "INT_SEXT",
    "SUBPIECE",
    "PTRADD",
    "PTRSUB",
    "INT_ADD",
    "MULTIEQUAL",
}


def _formal_atom_for_slot(function: dict[str, Any], slot: int) -> str:
    candidates: set[str] = set()
    for parameter in list(function.get("parameters", []) or []):
        parameter = dict(parameter or {})
        candidate_slot = parameter.get(
            "parameter_slot", parameter.get("index")
        )
        if candidate_slot == slot and str(parameter.get("value_id", "")):
            candidates.add(str(parameter["value_id"]))
    for op in list(function.get("pcode_ops", []) or []):
        nodes = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
        if isinstance(op.get("output"), dict):
            nodes.append(dict(op["output"]))
        for node in nodes:
            if (
                node.get("parameter_slot") == slot
                and bool(node.get("is_input"))
                and str(node.get("value_id", ""))
            ):
                candidates.add(str(node["value_id"]))
    return next(iter(candidates)) if len(candidates) == 1 else ""


def _origin_load_site(
    node: dict[str, Any],
    *,
    function_id: str,
    runtime: dataflow_objects.RuntimeObjectIndex,
    depth: int = 0,
    seen: set[str] | None = None,
) -> str:
    if depth > 12:
        return ""
    atom = dataflow_objects.identity(node)
    seen = set(seen or set())
    if atom and atom in seen:
        return ""
    if atom:
        seen.add(atom)
    entry = runtime.ops_by_site.get(str(node.get("def_site_id", "")))
    if not entry or entry[0] != function_id:
        return ""
    op = entry[1]
    mnemonic = str(op.get("mnemonic", ""))
    if mnemonic == "LOAD":
        return str(op.get("site_id", ""))
    if mnemonic not in _LOCAL_POINTER_TRANSFERS:
        return ""
    origins = {
        _origin_load_site(
            dict(item or {}),
            function_id=function_id,
            runtime=runtime,
            depth=depth + 1,
            seen=seen,
        )
        for item in list(op.get("inputs", []) or [])
        if not bool(dict(item or {}).get("is_constant"))
    }
    origins.discard("")
    return next(iter(origins)) if len(origins) == 1 else ""


def _dispatch_contract(
    function_id: str,
    receiver_slot: int,
    payload_slot: int,
    *,
    functions: dict[str, dict[str, Any]],
    runtime: dataflow_objects.RuntimeObjectIndex,
    depth: int = 0,
    seen: set[tuple[str, int, int]] | None = None,
) -> dict[str, Any] | None:
    """Resolve a direct-wrapper chain ending in receiver-field CALLIND."""

    if depth > 4:
        return None
    state = (function_id, receiver_slot, payload_slot)
    seen = set(seen or set())
    if state in seen:
        return None
    seen.add(state)
    function = functions.get(function_id)
    if function is None:
        return None
    receiver_root = f"obj:formal:{function_id}:{receiver_slot}"
    payload_root = f"obj:formal:{function_id}:{payload_slot}"
    results: list[dict[str, Any]] = []

    for op in list(function.get("pcode_ops", []) or []):
        mnemonic = str(op.get("mnemonic", ""))
        if mnemonic == "CALLIND":
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            if not inputs:
                continue
            target_binding = runtime.resolve(inputs[0], function_id)
            if not target_binding or str(
                target_binding.get("root_object_id", "")
            ) != receiver_root:
                continue
            payload_indices = []
            for index, actual in enumerate(_call_actuals(op)):
                binding = runtime.resolve(actual, function_id)
                if binding and str(binding.get("root_object_id", "")) == payload_root:
                    payload_indices.append(index)
            callback_offsets = _field_offsets(
                list(target_binding.get("access_path", []) or [])
            )
            if len(payload_indices) == 1 and callback_offsets:
                results.append(
                    {
                        "dispatch_function_id": function_id,
                        "dispatch_site_id": str(op.get("site_id", "")),
                        "callback_field_offset": callback_offsets[-1],
                        "handler_payload_slot": payload_indices[0],
                        "wrapper_chain": [],
                    }
                )
        elif mnemonic == "CALL":
            target_id = str(
                dict(op.get("call", {}) or {}).get("target_function_id", "")
            )
            if target_id not in functions:
                continue
            receiver_actuals: list[int] = []
            payload_actuals: list[int] = []
            for index, actual in enumerate(_call_actuals(op)):
                binding = runtime.resolve(actual, function_id)
                root = str(dict(binding or {}).get("root_object_id", ""))
                if root == receiver_root:
                    receiver_actuals.append(index)
                if root == payload_root:
                    payload_actuals.append(index)
            if len(receiver_actuals) != 1 or len(payload_actuals) != 1:
                continue
            nested = _dispatch_contract(
                target_id,
                receiver_actuals[0],
                payload_actuals[0],
                functions=functions,
                runtime=runtime,
                depth=depth + 1,
                seen=seen,
            )
            if nested:
                nested = dict(nested)
                nested["wrapper_chain"] = [
                    {
                        "function_id": function_id,
                        "site_id": str(op.get("site_id", "")),
                        "target_function_id": target_id,
                        "receiver_actual_index": receiver_actuals[0],
                        "payload_actual_index": payload_actuals[0],
                    }
                ] + list(nested.get("wrapper_chain", []) or [])
                results.append(nested)
    unique = {
        (
            str(row.get("dispatch_site_id", "")),
            int(row.get("callback_field_offset", -1)),
            int(row.get("handler_payload_slot", -1)),
        ): row
        for row in results
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _object_base_address(object_id: str) -> int | None:
    parts = object_id.split(":")
    if len(parts) < 3 or parts[0] != "obj":
        return None
    if parts[1] not in {"symbol", "ram"}:
        return None
    try:
        return int(parts[2], 16)
    except ValueError:
        return None


def build_event_queue_candidates(
    program_facts: dict[str, Any],
    *,
    runtime: dataflow_objects.RuntimeObjectIndex,
    literal_words: dict[int, int],
    exact_access_edges: list[dict[str, Any]],
    source_associations: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Recover Source-associated record queue transfers from function bodies.

    Recognition is structural: formal parameters are stored into distinct
    fields of one static record, the same fields are loaded by a consumer, and
    those values reach a receiver-field indirect dispatch.
    """

    functions = runtime.functions
    targets = executable_targets(program_facts)
    writes_by_function_object: dict[
        tuple[str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    reads_by_function_object: dict[
        tuple[str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    for edge in exact_access_edges:
        kind = str(edge.get("edge_kind", ""))
        key = (
            str(edge.get("function_id", "")),
            str(edge.get("object_id", "")),
        )
        if kind == "OBJECT_WRITE":
            writes_by_function_object[key].append(edge)
        elif kind == "OBJECT_READ":
            reads_by_function_object[key].append(edge)

    write_summaries: list[dict[str, Any]] = []
    for (function_id, object_id), edges in writes_by_function_object.items():
        function = functions.get(function_id, {})
        if not function or not object_id:
            continue
        fields: dict[int, dict[str, Any]] = {}
        for edge in edges:
            site_id = str(edge.get("site_id", ""))
            op_entry = runtime.ops_by_site.get(site_id)
            if not op_entry:
                continue
            inputs = [
                dict(item or {})
                for item in list(op_entry[1].get("inputs", []) or [])
            ]
            if len(inputs) < 2:
                continue
            stored = inputs[-1]
            slot = stored.get("parameter_slot")
            offset = edge.get("region_offset")
            extent = edge.get("region_extent")
            if not isinstance(slot, int) or not isinstance(offset, int):
                continue
            if not isinstance(extent, int) or extent <= 0:
                continue
            fields[offset] = {
                "formal_slot": slot,
                "extent": extent,
                "site_id": site_id,
                "value_atom_id": dataflow_objects.identity(stored),
            }
        pointer_fields = {
            offset: row
            for offset, row in fields.items()
            if int(row.get("extent", 0)) in {4, 8}
        }
        if len(pointer_fields) >= 2:
            write_summaries.append(
                {
                    "function_id": function_id,
                    "object_id": object_id,
                    "fields": fields,
                }
            )

    reader_contracts: list[dict[str, Any]] = []
    for (reader_id, object_id), edges in reads_by_function_object.items():
        reader = functions.get(reader_id, {})
        if not reader:
            continue
        load_by_site = {
            str(edge.get("site_id", "")): edge for edge in edges
        }
        for op in list(reader.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALL":
                continue
            target_id = str(
                dict(op.get("call", {}) or {}).get("target_function_id", "")
            )
            if target_id not in functions:
                continue
            actual_origins: dict[int, dict[str, Any]] = {}
            for index, actual in enumerate(_call_actuals(op)):
                load_site = _origin_load_site(
                    actual,
                    function_id=reader_id,
                    runtime=runtime,
                )
                load_edge = load_by_site.get(load_site)
                if load_edge:
                    actual_origins[index] = load_edge
            for receiver_index, receiver_edge in actual_origins.items():
                for payload_index, payload_edge in actual_origins.items():
                    if receiver_index == payload_index:
                        continue
                    receiver_offset = receiver_edge.get("region_offset")
                    payload_offset = payload_edge.get("region_offset")
                    if receiver_offset == payload_offset:
                        continue
                    dispatch = _dispatch_contract(
                        target_id,
                        receiver_index,
                        payload_index,
                        functions=functions,
                        runtime=runtime,
                    )
                    if dispatch:
                        reader_contracts.append(
                            {
                                "reader_function_id": reader_id,
                                "object_id": object_id,
                                "reader_call_site_id": str(op.get("site_id", "")),
                                "receiver_offset": receiver_offset,
                                "payload_offset": payload_offset,
                                "receiver_load_site_id": str(
                                    receiver_edge.get("site_id", "")
                                ),
                                "payload_load_site_id": str(
                                    payload_edge.get("site_id", "")
                                ),
                                "dispatch": dispatch,
                            }
                        )

    by_atom, by_object = source_association.association_index(source_associations)
    calls_to: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for caller_id, caller in functions.items():
        for op in list(caller.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALL":
                continue
            target_id = str(
                dict(op.get("call", {}) or {}).get("target_function_id", "")
            )
            if target_id:
                calls_to[target_id].append((caller_id, op))

    candidates: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for write in write_summaries:
        matching_readers = [
            row
            for row in reader_contracts
            if str(row.get("object_id", "")) == str(write.get("object_id", ""))
            and row.get("receiver_offset") in write["fields"]
            and row.get("payload_offset") in write["fields"]
        ]
        for reader in matching_readers:
            receiver_field = write["fields"][reader["receiver_offset"]]
            payload_field = write["fields"][reader["payload_offset"]]
            for caller_id, call_op in calls_to.get(
                str(write.get("function_id", "")), []
            ):
                actuals = _call_actuals(call_op)
                receiver_slot = int(receiver_field["formal_slot"])
                payload_slot = int(payload_field["formal_slot"])
                if max(receiver_slot, payload_slot) >= len(actuals):
                    continue
                receiver_actual = actuals[receiver_slot]
                payload_actual = actuals[payload_slot]
                payload_atom = dataflow_objects.identity(payload_actual)
                payload_binding = runtime.resolve(payload_actual, caller_id)
                payload_objects = {
                    str(dict(payload_binding or {}).get("object_id", "")),
                    str(dict(payload_binding or {}).get("root_object_id", "")),
                }
                associations = list(by_atom.get((caller_id, payload_atom), []))
                if not associations:
                    associations.extend(
                        row
                        for object_id in payload_objects
                        if object_id
                        for row in by_object.get(object_id, [])
                    )
                unique_associations = {
                    str(row.get("association_id", "")): row
                    for row in associations
                    if str(row.get("association_id", ""))
                }
                if not unique_associations:
                    continue

                receiver_binding = runtime.resolve(receiver_actual, caller_id)
                receiver_object_id = str(
                    dict(receiver_binding or {}).get(
                        "root_object_id",
                        dict(receiver_binding or {}).get("object_id", ""),
                    )
                )
                receiver_base = _object_base_address(receiver_object_id)
                callback_offset = int(
                    dict(reader.get("dispatch", {}) or {}).get(
                        "callback_field_offset", -1
                    )
                )
                callback_value = (
                    literal_words.get(receiver_base + callback_offset)
                    if receiver_base is not None and callback_offset >= 0
                    else None
                )
                handler = (
                    targets.get(callback_value & ~1)
                    if isinstance(callback_value, int)
                    else None
                )
                if handler is None:
                    blockers.append(
                        {
                            "reason": "event_receiver_callback_target_unresolved",
                            "function_id": caller_id,
                            "site_id": str(call_op.get("site_id", "")),
                            "object_id": receiver_object_id,
                            "evidence": {
                                "callback_field_offset": callback_offset,
                            },
                        }
                    )
                    continue
                handler_id = str(handler.get("function_id", ""))
                handler_payload_slot = int(
                    dict(reader.get("dispatch", {}) or {}).get(
                        "handler_payload_slot", -1
                    )
                )
                handler_atom = _formal_atom_for_slot(
                    handler, handler_payload_slot
                )
                if not handler_atom:
                    blockers.append(
                        {
                            "reason": "event_handler_payload_formal_unresolved",
                            "function_id": handler_id,
                            "site_id": str(call_op.get("site_id", "")),
                        }
                    )
                    continue

                source_ids = sorted(
                    {
                        str(row.get("source_id", ""))
                        for row in unique_associations.values()
                        if str(row.get("source_id", ""))
                    }
                )
                lineage = sorted(
                    {
                        str(row.get("source_definition_id", ""))
                        for row in unique_associations.values()
                        if str(row.get("source_definition_id", ""))
                    }
                )
                token = hashlib.sha256(
                    (
                        str(call_op.get("site_id", ""))
                        + "|"
                        + str(write.get("object_id", ""))
                        + "|"
                        + handler_id
                        + "|"
                        + str(reader.get("payload_offset", ""))
                    ).encode()
                ).hexdigest()[:20]
                object_id = str(write.get("object_id", ""))
                write_edge_id = f"event-channel-write:{token}"
                read_edge_id = f"event-channel-read:{token}"
                region = {
                    "object_id": object_id,
                    "base_object_id": object_id,
                    "offset": int(reader["payload_offset"]),
                    "extent": int(payload_field["extent"]),
                    "size": int(payload_field["extent"]),
                    "extent_kind": "EVENT_RECORD_PAYLOAD_FIELD",
                }
                candidates.append(
                    {
                        "candidate_id": f"event-channel:{token}",
                        "object_id": object_id,
                        "base_object_id": object_id,
                        "region": region,
                        "storage_kind": "STATIC_WRITABLE_DATA",
                        "transfer_semantics": "OBJECT_REFERENCE",
                        "analysis_precision": "MAY",
                        "recognition": "heuristic",
                        "source_ids": source_ids,
                        "source_id": source_ids[0] if source_ids else "",
                        "source_lineage_ids": lineage,
                        "reference_binding": {
                            "producer_atom_id": payload_atom,
                            "consumer_atom_id": handler_atom,
                            "pointee_object_id": str(
                                dict(payload_binding or {}).get(
                                    "root_object_id",
                                    dict(payload_binding or {}).get(
                                        "object_id", ""
                                    ),
                                )
                            ),
                            "pointee_access_path": list(
                                dict(payload_binding or {}).get(
                                    "access_path", []
                                )
                            ),
                        },
                        "writers": [
                            {
                                "edge_id": write_edge_id,
                                "function_id": caller_id,
                                "site_id": str(call_op.get("site_id", "")),
                                "value_atom_id": payload_atom,
                                "value_id": str(payload_actual.get("value_id", "")),
                                "value_object_id": str(
                                    payload_actual.get("object_id", "")
                                ),
                            }
                        ],
                        "readers": [
                            {
                                "edge_id": read_edge_id,
                                "function_id": handler_id,
                                "site_id": str(
                                    dict(reader.get("dispatch", {}) or {}).get(
                                        "dispatch_site_id", ""
                                    )
                                ),
                                "value_atom_id": handler_atom,
                                "value_id": handler_atom,
                                "value_object_id": f"param:{handler_id}:{handler_payload_slot}",
                            }
                        ],
                        "evidence_level": "BODY_PROVED_EVENT_QUEUE_CONTRACT",
                        "evidence": {
                            "queue_mutator_function_id": str(
                                write.get("function_id", "")
                            ),
                            "physical_store_site_id": str(
                                payload_field.get("site_id", "")
                            ),
                            "physical_load_site_id": str(
                                reader.get("payload_load_site_id", "")
                            ),
                            "receiver_load_site_id": str(
                                reader.get("receiver_load_site_id", "")
                            ),
                            "receiver_object_id": receiver_object_id,
                            "receiver_callback_field_offset": callback_offset,
                            "dispatch": dict(reader.get("dispatch", {}) or {}),
                            "source_association_ids": sorted(
                                unique_associations
                            ),
                        },
                    }
                )
    unique = {
        str(row.get("candidate_id", "")): row
        for row in candidates
        if str(row.get("candidate_id", ""))
    }
    return [unique[key] for key in sorted(unique)], blockers
