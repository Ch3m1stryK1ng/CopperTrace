#!/usr/bin/env python3
"""Build a callgraph-compatible ChannelGraph v2 from CopperTrace seeds.

The existing CopperTrace ChannelGraph remains the object-recovery baseline.
This adapter converts Ghidra ProgramFacts into MemoryAccessIndex, invokes the
existing builder, and enriches its context-level objects with exact High
P-code CALL/LOAD/STORE edges for sink-backward traversal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


ROOT = Path(__file__).resolve().parents[1]
SOURCEAGENT_ROOT = ROOT
if str(SOURCEAGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCEAGENT_ROOT))

from sourceagent.pipeline.channel_graph import build_channel_graph  # noqa: E402
from sourceagent.pipeline.models import (  # noqa: E402
    MemoryAccess,
    MemoryAccessIndex,
    MemoryMap,
    MemoryRegion,
)

import device_dispatch_resolver  # noqa: E402
import dataflow_objects  # noqa: E402
import ccc_effect_resolver  # noqa: E402
import container_alias_resolver  # noqa: E402
import function_effect_resolver  # noqa: E402
import memory_access_facts  # noqa: E402
import object_reference_ccc  # noqa: E402
import runtime_callback_resolver  # noqa: E402
import shared_object_miner  # noqa: E402
import sink_artifact_schema  # noqa: E402
import source_association  # noqa: E402


SRAM_START = 0x20000000
SRAM_END = 0x3FFFFFFF
DEFAULT_PRIMITIVE_REGISTRY = (
    ROOT / "registries" / "deterministic_sink_seeds.v1.json"
)


def stable_region_id(base_object_id: str, offset: int, extent: int) -> str:
    """Return an address/name-independent identity for one byte region."""

    return f"region:{base_object_id}:offset:{offset:x}:extent:{extent:x}"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def apply_resolved_dispatch_targets(
    program_facts: dict[str, Any], resolution: dict[str, Any]
) -> int:
    """Attach only uniquely proven CALLIND targets to the analysis copy.

    The original ProgramFacts artifact remains immutable. Ambiguous and
    unresolved dispatches never become Callgraph edges.
    """

    targets_by_site: dict[str, dict[str, Any]] = {}
    conflicting_sites: set[str] = set()
    for row in list(resolution.get("resolved", []) or []):
        row = dict(row or {})
        site_id = str(dict(row.get("callsite", {}) or {}).get("site_id", ""))
        target = dict(row.get("target", {}) or {})
        target_id = str(target.get("function_id", ""))
        if not site_id or not target_id:
            continue
        previous = targets_by_site.get(site_id)
        if previous and str(dict(previous.get("target", {}) or {}).get("function_id", "")) != target_id:
            conflicting_sites.add(site_id)
            continue
        targets_by_site[site_id] = row
    for site_id in conflicting_sites:
        targets_by_site.pop(site_id, None)

    known_functions = {
        str(function.get("function_id", ""))
        for function in list(program_facts.get("functions", []) or [])
        if str(function.get("function_id", ""))
    }
    applied = 0
    for function in list(program_facts.get("functions", []) or []):
        parameter_objects = {
            int(parameter.get("index")): str(parameter.get("object_id", ""))
            for parameter in list(function.get("parameters", []) or [])
            if isinstance(parameter.get("index"), int)
        }
        parameter_values: dict[int, str] = {}
        for candidate_op in list(function.get("pcode_ops", []) or []):
            candidate_nodes = list(candidate_op.get("inputs", []) or [])
            if isinstance(candidate_op.get("output"), dict):
                candidate_nodes.append(candidate_op["output"])
            for node in candidate_nodes:
                slot = dict(node or {}).get("parameter_slot")
                value_id = str(dict(node or {}).get("value_id", ""))
                if isinstance(slot, int) and value_id and bool(dict(node or {}).get("is_input")):
                    parameter_values.setdefault(slot, value_id)
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALLIND":
                continue
            row = targets_by_site.get(str(op.get("site_id", "")))
            if not row:
                continue
            target = dict(row.get("target", {}) or {})
            target_id = str(target.get("function_id", ""))
            if target_id not in known_functions:
                continue
            call = dict(op.get("call", {}) or {})
            argument_object_ids = list(call.get("argument_object_ids", []) or [])
            argument_value_ids = list(call.get("argument_value_ids", []) or [])
            argument_atom_ids = list(call.get("argument_atom_ids", []) or [])
            for binding in list(row.get("formal_identity_bindings", []) or []):
                caller_slot = binding.get("caller_parameter_slot")
                target_slot = binding.get("target_parameter_slot")
                if not isinstance(caller_slot, int) or not isinstance(target_slot, int):
                    continue
                while len(argument_object_ids) <= target_slot:
                    argument_object_ids.append("")
                while len(argument_value_ids) <= target_slot:
                    argument_value_ids.append("")
                while len(argument_atom_ids) <= target_slot:
                    argument_atom_ids.append("")
                argument_object_ids[target_slot] = parameter_objects.get(caller_slot, "")
                argument_value_ids[target_slot] = parameter_values.get(caller_slot, "")
                argument_atom_ids[target_slot] = (
                    parameter_values.get(caller_slot, "")
                    or parameter_objects.get(caller_slot, "")
                )
            call.update(
                {
                    "target_function_id": target_id,
                    "target_function": str(target.get("function", "")),
                    "resolution_kind": str(row.get("resolution_kind", "")),
                    "resolution_evidence": list(row.get("evidence", []) or []),
                    "argument_object_ids": argument_object_ids,
                    "argument_value_ids": argument_value_ids,
                    "argument_atom_ids": argument_atom_ids,
                    "formal_identity_bindings": list(
                        row.get("formal_identity_bindings", []) or []
                    ),
                }
            )
            op["call"] = call
            applied += 1
    return applied


def materialize_finite_dispatch_call_edges(
    program_facts: dict[str, Any],
    resolution: dict[str, Any],
    resolver: "DataObjectResolver",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Materialize every finite-table CALLIND candidate as one MAY edge.

    Unique targets are attached to ProgramFacts by
    :func:`apply_resolved_dispatch_targets` and are emitted by the ordinary
    Callgraph builder.  This function handles only finite non-singleton target
    sets.  It preserves the original callsite actuals and never chooses one
    target from the set.
    """

    operations: dict[str, tuple[str, dict[str, Any]]] = {}
    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        for op in list(function.get("pcode_ops", []) or []):
            site_id = str(op.get("site_id", ""))
            if site_id and str(op.get("mnemonic", "")) == "CALLIND":
                operations[site_id] = (function_id, op)

    edges: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for raw in list(resolution.get("resolved", []) or []):
        row = dict(raw or {})
        if str(row.get("resolution", "")) != "FINITE_TABLE_MAY_TARGET":
            continue
        callsite = dict(row.get("callsite", {}) or {})
        site_id = str(callsite.get("site_id", ""))
        target = dict(row.get("target", {}) or {})
        target_id = str(target.get("function_id", ""))
        operation = operations.get(site_id)
        if operation is None or not target_id:
            blockers.append(
                {
                    "reason": "finite_callind_callsite_or_target_unresolved",
                    "site_id": site_id,
                    "target_function_id": target_id,
                }
            )
            continue
        caller_id, op = operation
        actuals = [
            dict(item or {})
            for item in list(row.get("original_actual_arguments", []) or [])
        ]
        if not actuals:
            actuals = [
                dict(item or {})
                for item in list(op.get("inputs", []) or [])[1:]
            ]
        positional = {
            int(binding.get("argument_index")): dict(binding or {})
            for binding in list(row.get("argument_bindings", []) or [])
            if isinstance(dict(binding or {}).get("argument_index"), int)
        }
        argument_bindings: list[dict[str, Any]] = []
        resolved_object_ids: list[str] = []
        for slot, actual in enumerate(actuals):
            resolved = object_from_varnode(actual, resolver)
            object_id = str(resolved[0]) if resolved else str(
                actual.get("object_id", "")
            )
            resolved_object_ids.append(object_id)
            metadata = positional.get(slot, {})
            argument_bindings.append(
                {
                    "slot": slot,
                    "atom_id": dataflow_objects.identity(actual),
                    "value_id": str(actual.get("value_id", "")),
                    "object_id": object_id,
                    "target_parameter_slot": metadata.get(
                        "target_parameter_slot", slot
                    ),
                    "target_formal_object_id": str(
                        metadata.get("target_formal_object_id", "")
                    ),
                }
            )
        edges.append(
            {
                "edge_id": f"call:{site_id}:{target_id}",
                "src_node_id": caller_id,
                "dst_node_id": target_id,
                "function_id": caller_id,
                "site_id": site_id,
                "edge_kind": "CALLIND",
                "resolution": "FINITE_TABLE_MAY_TARGET",
                "resolution_kind": str(row.get("resolution_kind", "")),
                "recognition": "heuristic",
                "analysis_precision": "MAY",
                "candidate_set_id": str(row.get("candidate_set_id", "")),
                "candidate_ordinal": row.get("candidate_ordinal"),
                "candidate_count": row.get("candidate_count"),
                "argument_bindings": argument_bindings,
                "argument_atom_ids": [
                    str(binding.get("atom_id", ""))
                    for binding in argument_bindings
                ],
                "argument_value_ids": [
                    str(binding.get("value_id", ""))
                    for binding in argument_bindings
                ],
                "argument_object_ids": [
                    str(actual.get("object_id", "")) for actual in actuals
                ],
                "resolved_argument_object_ids": resolved_object_ids,
                "formal_parameter_object_ids": [
                    str(binding.get("target_formal_object_id", ""))
                    for binding in argument_bindings
                ],
                "resolution_evidence": list(row.get("evidence", []) or []),
                "bound_output_effects": [],
            }
        )
    return sorted(edges, key=lambda edge: str(edge.get("edge_id", ""))), blockers


def bind_fixed_output_effects(
    program_facts: dict[str, Any],
    call_edges: list[dict[str, Any]],
    value_object_bindings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Bind body-derived output STOREs to resolved CALL relations."""

    object_candidates: dict[str, set[str]] = defaultdict(set)
    for raw in value_object_bindings:
        row = dict(raw or {})
        object_id = str(row.get("object_id", ""))
        if not object_id:
            continue
        for atom_id in {
            str(row.get("atom_id", "")),
            str(row.get("value_id", "")),
        } - {""}:
            object_candidates[atom_id].add(object_id)
    for edge in call_edges:
        for slot, atom_id in enumerate(list(edge.get("argument_atom_ids", []) or [])):
            object_ids = list(edge.get("resolved_argument_object_ids", []) or [])
            object_id = str(object_ids[slot]) if slot < len(object_ids) else ""
            if str(atom_id) and object_id:
                object_candidates[str(atom_id)].add(object_id)
        for slot, value_id in enumerate(list(edge.get("argument_value_ids", []) or [])):
            object_ids = list(edge.get("resolved_argument_object_ids", []) or [])
            object_id = str(object_ids[slot]) if slot < len(object_ids) else ""
            if str(value_id) and object_id:
                object_candidates[str(value_id)].add(object_id)
    resolved_object_by_atom = {
        atom_id: next(iter(object_ids))
        for atom_id, object_ids in object_candidates.items()
        if len(object_ids) == 1
    }
    functions = {
        str(function.get("function_id", "")): function
        for function in list(program_facts.get("functions", []) or [])
        if str(function.get("function_id", ""))
    }
    calls_by_site: dict[str, list[dict[str, Any]]] = defaultdict(list)
    calls_to: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in call_edges:
        calls_by_site[str(edge.get("site_id", ""))].append(edge)
        calls_to[str(edge.get("dst_node_id", ""))].append(edge)
    resolver = function_effect_resolver.FunctionEffectResolver(
        functions=functions,
        calls_by_site=dict(calls_by_site),
        calls_to=dict(calls_to),
        resolved_object_by_atom=resolved_object_by_atom,
        identity=dataflow_objects.identity,
        public_value=lambda node: str(dict(node or {}).get("value_id", "")),
        same_object=lambda left, right: bool(left) and left == right,
        limits=function_effect_resolver.ResolutionLimits(
            max_call_depth=8,
            max_ops_per_summary=2000,
            max_alternatives=16,
        ),
    )
    effects, blockers = resolver.bind_output_effects_to_calls()
    effects_by_edge: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for effect in effects:
        effects_by_edge[str(effect.get("call_edge_id", ""))].append(effect)
    for edge in call_edges:
        edge_id = str(edge.get("edge_id", ""))
        if edge_id in effects_by_edge:
            edge["bound_output_effects"] = sorted(
                effects_by_edge[edge_id],
                key=lambda row: str(row.get("effect_id", "")),
            )
    return effects, blockers


def apply_body_proved_callback_targets(
    program_facts: dict[str, Any],
    call_edges: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> tuple[int, list[dict[str, Any]]]:
    """Use optional body summaries only to resolve concrete CALLIND targets."""

    targets_by_site: dict[str, set[str]] = defaultdict(set)
    evidence_by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in candidates:
        evidence = dict(candidate.get("evidence", {}) or {})
        dispatch = dict(evidence.get("dispatch", {}) or {})
        site_id = str(dispatch.get("dispatch_site_id", ""))
        for reader in list(candidate.get("readers", []) or []):
            target_id = str(dict(reader or {}).get("function_id", ""))
            if site_id and target_id:
                targets_by_site[site_id].add(target_id)
                evidence_by_pair[(site_id, target_id)] = {
                    "queue_mutator_function_id": str(
                        evidence.get("queue_mutator_function_id", "")
                    ),
                    "physical_store_site_id": str(
                        evidence.get("physical_store_site_id", "")
                    ),
                    "physical_load_site_id": str(
                        evidence.get("physical_load_site_id", "")
                    ),
                    "receiver_load_site_id": str(
                        evidence.get("receiver_load_site_id", "")
                    ),
                }

    unique_targets = {
        site_id: next(iter(targets))
        for site_id, targets in targets_by_site.items()
        if len(targets) == 1
    }
    blockers = [
        {
            "reason": "body_proved_callback_target_not_unique",
            "site_id": site_id,
            "candidate_target_ids": sorted(targets),
        }
        for site_id, targets in targets_by_site.items()
        if len(targets) != 1
    ]
    applied = 0
    for function in list(program_facts.get("functions", []) or []):
        for op in list(function.get("pcode_ops", []) or []):
            site_id = str(op.get("site_id", ""))
            target_id = unique_targets.get(site_id, "")
            if str(op.get("mnemonic", "")) != "CALLIND" or not target_id:
                continue
            call = dict(op.get("call", {}) or {})
            previous = str(call.get("target_function_id", ""))
            if previous and previous != target_id:
                blockers.append(
                    {
                        "reason": "body_proved_callback_conflicts_with_existing_target",
                        "site_id": site_id,
                        "existing_target_id": previous,
                        "candidate_target_id": target_id,
                    }
                )
                continue
            call.update(
                {
                    "target_function_id": target_id,
                    "resolution_kind": "BODY_PROVED_STATIC_CALLBACK_DESCRIPTOR",
                    "resolution_evidence": [
                        evidence_by_pair.get((site_id, target_id), {})
                    ],
                }
            )
            op["call"] = call
            applied += int(previous != target_id)

    for edge in call_edges:
        site_id = str(edge.get("site_id", ""))
        target_id = unique_targets.get(site_id, "")
        if str(edge.get("edge_kind", "")) != "CALLIND" or not target_id:
            continue
        edge["dst_node_id"] = target_id
        edge["resolution"] = "EXACT_INDIRECT_TARGET"
        edge["resolution_kind"] = "BODY_PROVED_STATIC_CALLBACK_DESCRIPTOR"
        edge["resolution_evidence"] = [
            evidence_by_pair.get((site_id, target_id), {})
        ]
    return applied, blockers


def normalize_channel_edge_v4(edge: dict[str, Any]) -> dict[str, Any]:
    """Normalize one relation without inventing a missing transfer atom."""

    row = dict(edge)
    kind = str(row.get("edge_kind", ""))
    reference = dict(row.get("reference_binding", {}) or {})
    recognition = str(row.get("recognition", ""))
    if recognition not in {"deterministic", "heuristic"}:
        recognition = (
            "deterministic"
            if bool(row.get("deterministic"))
            or str(row.get("analysis_precision", "")) == "EXACT"
            else "heuristic"
        )
    row["recognition"] = recognition
    row["traversable"] = True
    source_ids = {
        str(item)
        for item in (
            list(row.get("source_ids", []) or [])
            + [row.get("source_id", "")]
        )
        if str(item)
    }
    if kind == "CHANNEL_WRITE":
        atom_id = str(
            row.get("stored_atom_id", "")
            or reference.get("producer_atom_id", "")
            or row.get("value_atom_id", "")
            or row.get("value_id", "")
        )
        if not atom_id:
            row["traversable"] = False
            row.setdefault("analysis_blockers", []).append(
                "channel_write_stored_atom_missing"
            )
        row["stored_atom_id"] = atom_id
        row["value_atom_id"] = str(row.get("value_atom_id", "") or atom_id)
        row["source_associated"] = bool(
            row.get("source_associated", bool(source_ids))
        )
    elif kind == "CHANNEL_READ":
        atom_id = str(
            row.get("loaded_atom_id", "")
            or reference.get("consumer_atom_id", "")
            or row.get("value_atom_id", "")
            or row.get("value_id", "")
        )
        if not atom_id:
            row["traversable"] = False
            row.setdefault("analysis_blockers", []).append(
                "channel_read_loaded_atom_missing"
            )
        row["loaded_atom_id"] = atom_id
        row["value_atom_id"] = str(row.get("value_atom_id", "") or atom_id)
        row["source_associated"] = bool(
            row.get("source_associated", bool(source_ids))
        )
    return row


def parse_int(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text, 16)
    except ValueError:
        return None


def varnode_address(node: dict[str, Any]) -> int | None:
    space = str(node.get("space", ""))
    offset = parse_int(node.get("offset"))
    if space == "ram" and offset is not None:
        return offset
    if bool(node.get("is_address")) and offset is not None:
        return offset
    if bool(node.get("is_constant")) and offset is not None and SRAM_START <= offset <= SRAM_END:
        return offset
    return None


def is_sram_address(address: int | None) -> bool:
    return address is not None and SRAM_START <= address <= SRAM_END


def looks_like_task_entry(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ("task", "thread", "worker", "work_q"))


def function_context(
    function: dict[str, Any], inferred: dict[str, tuple[set[str], str]] | None = None
) -> tuple[list[str], str]:
    function_id = str(function.get("function_id", ""))
    if inferred and function_id in inferred:
        contexts, provenance = inferred[function_id]
        return sorted(contexts), provenance
    name = str(function.get("name", ""))
    if bool(function.get("is_interrupt_entry")):
        return [f"ctx:isr:{function_id}"], "DETERMINISTIC_VECTOR_ISR"
    if name == "main":
        return ["ctx:main"], "DETERMINISTIC_MAIN"
    if looks_like_task_entry(name):
        return [f"ctx:task:{function_id}"], "HEURISTIC_TASK_ENTRY"
    return ["ctx:unknown"], "UNKNOWN_EXECUTION_CONTEXT"


def infer_execution_contexts(
    program_facts: dict[str, Any]
) -> dict[str, tuple[set[str], str]]:
    """Propagate main/ISR/task execution contexts over direct Callgraph edges."""

    functions = list(program_facts.get("functions", []) or [])
    by_id = {str(function.get("function_id", "")): function for function in functions}
    callees: dict[str, set[str]] = defaultdict(set)
    for function_id, function in by_id.items():
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALL":
                continue
            target = str(dict(op.get("call", {}) or {}).get("target_function_id", ""))
            if target in by_id:
                callees[function_id].add(target)

    contexts: dict[str, set[str]] = defaultdict(set)
    provenance: dict[str, set[str]] = defaultdict(set)
    queue: deque[tuple[str, str, str]] = deque()
    for function_id, function in by_id.items():
        name = str(function.get("name", ""))
        if bool(function.get("is_interrupt_entry")):
            queue.append((function_id, f"ctx:isr:{function_id}", "CALLGRAPH_FROM_VECTOR_ISR"))
        if name == "main":
            queue.append((function_id, "ctx:main", "CALLGRAPH_FROM_MAIN"))
        if looks_like_task_entry(name):
            queue.append((function_id, f"ctx:task:{function_id}", "CALLGRAPH_FROM_HEURISTIC_TASK_ENTRY"))

    while queue:
        function_id, context_id, source = queue.popleft()
        if context_id in contexts[function_id]:
            continue
        contexts[function_id].add(context_id)
        provenance[function_id].add(source)
        for callee in sorted(callees.get(function_id, set())):
            queue.append((callee, context_id, source))

    return {
        function_id: (
            values or {"ctx:unknown"},
            "+".join(sorted(provenance.get(function_id, set())))
            or "UNKNOWN_EXECUTION_CONTEXT",
        )
        for function_id, values in (
            (function_id, contexts.get(function_id, set())) for function_id in by_id
        )
    }


def _deterministic_context_row(row: dict[str, Any]) -> bool:
    if bool(row.get("deterministic")):
        return True
    evidence = str(row.get("evidence_level", "")).upper()
    resolution = str(row.get("resolution", row.get("recovery", ""))).upper()
    provenance = str(row.get("provenance", "")).upper()
    return (
        evidence.startswith("DETERMINISTIC")
        or resolution in {"DETERMINISTIC", "EXACT", "PROVED"}
        or provenance.startswith("DETERMINISTIC")
    )


def infer_deterministic_execution_contexts(
    program_facts: dict[str, Any]
) -> dict[str, tuple[set[str], str]]:
    """Recover only execution contexts backed by structured entry facts.

    Vector ISR entries and the imported ``main`` entry are deterministic roots.
    Additional task/thread roots must be supplied as structured deterministic
    context facts; function-name tokens never create a strict context.
    """

    functions = list(program_facts.get("functions", []) or [])
    by_id = {str(function.get("function_id", "")): function for function in functions}
    callees: dict[str, set[str]] = defaultdict(set)
    call_kinds: dict[tuple[str, str], set[str]] = defaultdict(set)
    for function_id, function in by_id.items():
        for op in list(function.get("pcode_ops", []) or []):
            mnemonic = str(op.get("mnemonic", ""))
            if mnemonic not in {"CALL", "CALLIND"}:
                continue
            target = str(dict(op.get("call", {}) or {}).get("target_function_id", ""))
            if target in by_id:
                callees[function_id].add(target)
                call_kinds[(function_id, target)].add(mnemonic)

    contexts: dict[str, set[str]] = defaultdict(set)
    provenance: dict[str, set[str]] = defaultdict(set)
    queue: deque[tuple[str, str, str]] = deque()

    for function_id, function in by_id.items():
        if bool(function.get("is_interrupt_entry")):
            queue.append(
                (function_id, f"ctx:isr:{function_id}", "DETERMINISTIC_VECTOR_ISR")
            )
        if str(function.get("name", "")) == "main":
            queue.append((function_id, "ctx:main", "DETERMINISTIC_MAIN_SYMBOL"))
        if bool(function.get("is_program_entry")) or bool(function.get("is_entry_point")):
            queue.append(
                (function_id, f"ctx:entry:{function_id}", "DETERMINISTIC_PROGRAM_ENTRY")
            )
        function_contexts = list(function.get("execution_contexts", []) or [])
        if function.get("execution_context_id"):
            function_contexts.append(
                {
                    "context_id": function.get("execution_context_id"),
                    "deterministic": function.get("execution_context_deterministic", False),
                    "provenance": function.get("execution_context_provenance", ""),
                }
            )
        for row in function_contexts:
            row = dict(row or {})
            context_id = str(row.get("context_id", row.get("id", "")))
            if context_id and _deterministic_context_row(row):
                queue.append(
                    (
                        function_id,
                        context_id,
                        str(row.get("provenance", "DETERMINISTIC_EXPLICIT_CONTEXT")),
                    )
                )

    for row in list(program_facts.get("execution_contexts", []) or []):
        row = dict(row or {})
        function_id = str(
            row.get("entry_function_id", row.get("function_id", ""))
        )
        context_id = str(row.get("context_id", row.get("id", "")))
        if function_id in by_id and context_id and _deterministic_context_row(row):
            queue.append(
                (
                    function_id,
                    context_id,
                    str(row.get("provenance", "DETERMINISTIC_EXPLICIT_CONTEXT")),
                )
            )

    while queue:
        function_id, context_id, source = queue.popleft()
        if context_id in contexts[function_id]:
            continue
        contexts[function_id].add(context_id)
        provenance[function_id].add(source)
        for callee in sorted(callees.get(function_id, set())):
            kinds = call_kinds[(function_id, callee)]
            hop = "EXACT_CALLIND" if kinds == {"CALLIND"} else "DIRECT_CALL"
            queue.append((callee, context_id, f"{source}+{hop}"))

    return {
        function_id: (
            contexts.get(function_id, set()),
            "+".join(sorted(provenance.get(function_id, set())))
            or "NO_DETERMINISTIC_EXECUTION_CONTEXT",
        )
        for function_id in by_id
    }


def program_facts_to_mai(
    program_facts: dict[str, Any], resolver: DataObjectResolver | None = None
) -> tuple[MemoryAccessIndex, MemoryMap]:
    accesses: list[MemoryAccess] = []
    decompiled_cache: dict[str, str] = {}
    isr_functions: list[str] = []
    resolver = resolver or DataObjectResolver(program_facts)

    for function in list(program_facts.get("functions", []) or []):
        name = str(function.get("name", ""))
        entry = parse_int(function.get("entry")) or 0
        decompiled_cache[name] = str(function.get("decompiled_c", ""))
        if bool(function.get("is_interrupt_entry")):
            isr_functions.append(name)
        for op in list(function.get("pcode_ops", []) or []):
            mnemonic = str(op.get("mnemonic", ""))
            inputs = list(op.get("inputs", []) or [])
            target: int | None = None
            width = 0
            if mnemonic == "LOAD" and inputs:
                resolved = resolver.resolve_address(dict(inputs[-1] or {}))
                target = resolved[0] if resolved else None
                width = int(dict(op.get("output", {}) or {}).get("size", 0) or 0)
                kind = "load"
            elif mnemonic == "STORE" and len(inputs) >= 2:
                resolved = resolver.resolve_address(dict(inputs[-2] or {}))
                target = resolved[0] if resolved else None
                width = int(dict(inputs[-1] or {}).get("size", 0) or 0)
                kind = "store"
            else:
                continue
            if not is_sram_address(target):
                continue
            accesses.append(
                MemoryAccess(
                    address=parse_int(op.get("instruction_address")) or 0,
                    kind=kind,
                    width=width,
                    target_addr=target,
                    base_provenance="GLOBAL_PTR",
                    in_isr=bool(function.get("is_interrupt_entry")),
                    function_name=name,
                    function_addr=entry,
                )
            )

    symbols: dict[str, int] = {}
    for symbol in list(program_facts.get("symbols", []) or []):
        address = parse_int(symbol.get("address"))
        name = str(symbol.get("name", ""))
        if name and is_sram_address(address):
            symbols[name] = int(address)

    binary = str(program_facts.get("binary", ""))
    mai = MemoryAccessIndex(
        binary_path=binary,
        accesses=accesses,
        isr_functions=isr_functions,
        global_symbol_table=symbols,
        decompiled_cache=decompiled_cache,
    )

    regions: list[MemoryRegion] = []
    for block in list(program_facts.get("memory_blocks", []) or []):
        start = parse_int(block.get("start"))
        end = parse_int(block.get("end"))
        if start is None or end is None or end < start:
            continue
        execute = bool(block.get("execute"))
        write = bool(block.get("write"))
        kind = "sram" if is_sram_address(start) else "flash" if execute else "data"
        permissions = "r" + ("w" if write else "") + ("x" if execute else "")
        regions.append(
            MemoryRegion(
                name=str(block.get("name", "")),
                base=start,
                size=end - start + 1,
                permissions=permissions,
                kind=kind,
            )
        )
    isr_addrs = [
        parse_int(function.get("entry")) or 0
        for function in list(program_facts.get("functions", []) or [])
        if bool(function.get("is_interrupt_entry"))
    ]
    memory_map = MemoryMap(
        binary_path=binary,
        arch=str(program_facts.get("language_id", "ARM:LE:32:Cortex")),
        base_address=parse_int(program_facts.get("image_base")) or 0,
        entry_point=0,
        regions=regions,
        isr_handler_addrs=isr_addrs,
    )
    return mai, memory_map


def source_rows(sources: dict[str, Any]) -> list[dict[str, Any]]:
    return list(sources.get("source_sites", []) or sources.get("confirmed_sources", []) or [])


def source_output_rows(source: dict[str, Any]) -> list[dict[str, Any]]:
    """Return unique Source outputs, including legacy single-output rows."""

    outputs: list[dict[str, Any]] = []
    raw_outputs = source.get("source_outputs", [])
    if isinstance(raw_outputs, list):
        outputs.extend(dict(output or {}) for output in raw_outputs)
    if isinstance(source.get("source_output"), dict):
        outputs.append(dict(source["source_output"]))
    outputs.append(
        {
            "role": "output_buffer",
            "kind": str(source.get("source_output_kind", "")),
            "expression": str(source.get("source_buffer", "")),
            "object_id": str(source.get("source_object_id", "")),
            "value_id": str(source.get("source_value_id", "")),
        }
    )
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for output in outputs:
        key = (
            str(output.get("role", "")),
            str(output.get("kind", "")),
            str(output.get("value_id", "")),
            str(output.get("object_id", "")),
        )
        if key in seen or not any(key):
            continue
        seen.add(key)
        unique.append(output)
    return unique


def sourceagent_label_rows(sources: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in source_rows(sources):
        proof = dict(source.get("proof", {}) or {})
        address = parse_int(str(source.get("site_id", "")).split(":")[-2]) or 0
        rows.append(
            {
                "label": str(source.get("label", "")),
                "address": address,
                "function_name": str(source.get("function", "")),
                "evidence_refs": [str(source.get("site_id", ""))],
                "facts": {
                    "buffer_cluster": parse_int_from_object_id(str(source.get("source_object_id", ""))),
                    "buffer_binding_object_id": str(source.get("source_object_id", "")),
                    "buffer_binding_confidence": 1.0 if source.get("decision") == "ACCEPT_DETERMINISTIC" else 0.6,
                    "source_context_hint": "ISR" if str(source.get("label", "")).startswith("ISR_") else "MAIN",
                    "source_signature": str(source.get("id", "")),
                    "proof": proof,
                },
            }
        )
    return rows


def parse_int_from_object_id(object_id: str) -> int:
    for token in str(object_id).split(":"):
        value = parse_int(token)
        if value is not None and SRAM_START <= value <= SRAM_END:
            return value
    return 0


def function_indexes(program_facts: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_name: dict[str, dict[str, Any]] = {}
    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        name = str(function.get("name", ""))
        if function_id:
            by_id[function_id] = function
        if name and name not in by_name:
            by_name[name] = function
    return by_id, by_name


def writable_data_ranges(program_facts: dict[str, Any]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for block in list(program_facts.get("memory_blocks", []) or []):
        if not bool(block.get("write")) or bool(block.get("execute")):
            continue
        start = parse_int(block.get("start"))
        end = parse_int(block.get("end"))
        if start is not None and end is not None and start <= end:
            ranges.append((start, end))
    return ranges


def writable_data_blocks(program_facts: dict[str, Any]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for block in list(program_facts.get("memory_blocks", []) or []):
        if not bool(block.get("write")) or bool(block.get("execute")):
            continue
        start = parse_int(block.get("start"))
        end = parse_int(block.get("end"))
        if start is None or end is None or start > end:
            continue
        blocks.append(
            {
                "name": str(block.get("name", "")),
                "start": start,
                "end": end,
                "read": bool(block.get("read", True)),
                "write": True,
                "execute": False,
            }
        )
    return sorted(blocks, key=lambda row: (row["start"], row["end"], row["name"]))


def in_writable_data(address: int | None, ranges: list[tuple[int, int]]) -> bool:
    return address is not None and any(start <= address <= end for start, end in ranges)


class DataObjectResolver:
    """Resolve High P-code pointer values to writable ELF objects.

    Cortex-M code commonly materializes a RAM pointer through a flash literal
    pool. Ghidra may expose the literal slot (`0x0800...`) as the varnode even
    though the loaded value is `0x2000...`. Reading only pointer-sized literal
    values closes that representation gap without guessing from variable names.
    """

    def __init__(self, program_facts: dict[str, Any]):
        self.writable_blocks = writable_data_blocks(program_facts)
        self.ranges = [
            (int(block["start"]), int(block["end"]))
            for block in self.writable_blocks
        ]
        self.ops_by_site = {
            str(op.get("site_id", "")): op
            for function in list(program_facts.get("functions", []) or [])
            for op in list(function.get("pcode_ops", []) or [])
            if str(op.get("site_id", ""))
        }
        self.functions_by_id = {
            str(function.get("function_id", "")): function
            for function in list(program_facts.get("functions", []) or [])
            if str(function.get("function_id", ""))
        }
        self.op_function_id: dict[str, str] = {}
        self.stack_named_roots: dict[tuple[str, str], int] = {}
        for function_id, function in self.functions_by_id.items():
            named_offsets: dict[str, list[int]] = defaultdict(list)
            for op in list(function.get("pcode_ops", []) or []):
                site_id = str(op.get("site_id", ""))
                if site_id:
                    self.op_function_id[site_id] = function_id
                nodes = [dict(op.get("output", {}) or {})]
                nodes.extend(
                    dict(item or {}) for item in list(op.get("inputs", []) or [])
                )
                for node in nodes:
                    name = str(node.get("high_name", "")).strip()
                    if not name or name == "UNNAMED":
                        continue
                    offset: int | None = None
                    if str(node.get("space", "")) == "stack":
                        text = str(node.get("offset", ""))
                        offset = (
                            -int(text[3:], 16)
                            if text.startswith("0x-")
                            else _signed_node_constant(node)
                        )
                    elif (
                        str(op.get("mnemonic", "")) == "PTRSUB"
                        and bool(node.get("is_constant"))
                    ):
                        candidate = _signed_node_constant(node)
                        if candidate is not None and candidate < 0:
                            offset = candidate
                    if offset is not None:
                        named_offsets[name].append(offset)
            for name, offsets in named_offsets.items():
                self.stack_named_roots[(function_id, name)] = min(offsets)
        self.literal_words: dict[int, int] = {}
        self.elf_object_symbols: list[tuple[int, int, str]] = []
        binary = Path(str(program_facts.get("binary", "")))
        if binary.is_file():
            with binary.open("rb") as stream:
                elf = ELFFile(stream)
                endian = "little" if elf.little_endian else "big"
                for segment in elf.iter_segments():
                    if segment["p_type"] != "PT_LOAD":
                        continue
                    start = int(segment["p_vaddr"])
                    data = segment.data()
                    for offset in range(0, max(0, len(data) - 3), 4):
                        self.literal_words[start + offset] = int.from_bytes(
                            data[offset:offset + 4], endian
                        )
                for section in elf.iter_sections():
                    if not isinstance(section, SymbolTableSection):
                        continue
                    for symbol in section.iter_symbols():
                        if symbol["st_info"]["type"] != "STT_OBJECT":
                            continue
                        start = int(symbol["st_value"])
                        size = int(symbol["st_size"])
                        name = str(symbol.name or "")
                        if (
                            name
                            and size > 0
                            and in_writable_data(start, self.ranges)
                            and in_writable_data(start + size - 1, self.ranges)
                        ):
                            self.elf_object_symbols.append(
                                (start, start + size - 1, name)
                            )
        self.elf_object_symbols = sorted(set(self.elf_object_symbols))
        symbols: list[tuple[int, str, str]] = []
        for symbol in list(program_facts.get("symbols", []) or []):
            address = parse_int(symbol.get("address"))
            name = str(symbol.get("name", ""))
            source = str(symbol.get("source", ""))
            # DEFAULT labels commonly describe individual bytes inside one
            # imported array (for example u8_t_ARRAY_20000859). Treating each
            # byte as a separate object breaks offset-preserving taint flow.
            if source == "DEFAULT":
                continue
            if address is not None and name and in_writable_data(address, self.ranges):
                symbols.append((address, name, str(symbol.get("object_id", ""))))
                size = parse_int(symbol.get("size"))
                if (
                    size is not None
                    and size > 0
                    and in_writable_data(address + size - 1, self.ranges)
                ):
                    self.elf_object_symbols.append(
                        (address, address + size - 1, name)
                    )
        self.elf_object_symbols = sorted(set(self.elf_object_symbols))
        self.symbols = sorted(set(symbols))
        self._address_cache: dict[str, tuple[int, str] | None] = {}
        self._object_cache: dict[int, dict[str, Any]] = {}

    def stack_descriptor(
        self, node: dict[str, Any], function_id: str
    ) -> tuple[int, int] | None:
        effective = _stack_pointer_offset(node, self.ops_by_site)
        descriptor = _stack_pointer_descriptor(node, self.ops_by_site)
        name = _stack_pointer_name(node, self.ops_by_site)
        if name and effective is not None:
            root = self.stack_named_roots.get((function_id, name))
            if root is not None:
                return root, effective - root
        return descriptor

    def resolve_address(
        self,
        node: dict[str, Any],
        *,
        depth: int = 0,
        seen: set[str] | None = None,
        memo: dict[tuple[str, int], tuple[int, str] | None] | None = None,
    ) -> tuple[int, str] | None:
        """Resolve one SSA pointer, reusing context-independent results.

        Whole-image Channelgraph construction asks about the same SSA values
        through outputs, inputs, memory facts, and alias bindings.  Successful
        resolutions are independent of the caller's traversal context and can
        always be reused.  A failed result is cached only for a top-level query
        so cycle-pruning in one recursive branch cannot suppress another path.
        """

        top_level = depth == 0 and not seen
        memo = memo if memo is not None else {}
        identity = (
            str(node.get("value_id", ""))
            or str(node.get("object_id", ""))
            or (
                f"{node.get('def_site_id', '')}:"
                f"{node.get('space', '')}:{node.get('offset', '')}:"
                f"{node.get('size', '')}"
            )
        )
        local_key = (identity, depth)
        if identity and local_key in memo:
            return memo[local_key]
        if identity in self._address_cache:
            cached = self._address_cache[identity]
            if cached is not None or top_level:
                return cached

        resolved = self._resolve_address_uncached(
            node,
            depth=depth,
            seen=seen,
            memo=memo,
        )
        if identity:
            memo[local_key] = resolved
        if resolved is not None or top_level:
            self._address_cache[identity] = resolved
        return resolved

    def _resolve_address_uncached(
        self,
        node: dict[str, Any],
        *,
        depth: int = 0,
        seen: set[str] | None = None,
        memo: dict[tuple[str, int], tuple[int, str] | None] | None = None,
    ) -> tuple[int, str] | None:
        if depth > 12:
            return None
        seen = set(seen or set())
        value_id = str(node.get("value_id", ""))
        if value_id and value_id in seen:
            return None
        if value_id:
            seen.add(value_id)
        raw = varnode_address(node)
        if in_writable_data(raw, self.ranges):
            return int(raw), "HIGH_PCODE_DIRECT_ADDRESS"
        if raw is not None:
            literal = self.literal_words.get(int(raw) & ~3)
            if in_writable_data(literal, self.ranges):
                byte_delta = int(raw) & 3
                return int(literal) + byte_delta, "ELF_LITERAL_POOL_POINTER"

        def_site = str(node.get("def_site_id", ""))
        op = self.ops_by_site.get(def_site)
        if not op:
            return None
        mnemonic = str(op.get("mnemonic", ""))
        inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
        if mnemonic == "CALL":
            target_id = str(dict(op.get("call", {}) or {}).get("target_function_id", ""))
            target = self.functions_by_id.get(target_id)
            resolved_returns: list[tuple[int, str]] = []
            if target:
                for return_op in list(target.get("pcode_ops", []) or []):
                    if str(return_op.get("mnemonic", "")) != "RETURN":
                        continue
                    for return_input in list(return_op.get("inputs", []) or [])[1:]:
                        return_input = dict(return_input or {})
                        if bool(return_input.get("is_constant")):
                            continue
                        resolved = self.resolve_address(
                            return_input,
                            depth=depth + 1,
                            seen=seen,
                            memo=memo,
                        )
                        if resolved:
                            resolved_returns.append(resolved)
            addresses = {item[0] for item in resolved_returns}
            if len(addresses) == 1:
                address = next(iter(addresses))
                return address, "DIRECT_CALL_RETURN_POINTER"
        if mnemonic in {"COPY", "CAST", "INDIRECT", "SUBPIECE"}:
            resolved_inputs = [
                resolved
                for item in inputs
                if not bool(item.get("is_constant"))
                for resolved in [
                    self.resolve_address(
                        item,
                        depth=depth + 1,
                        seen=set(seen),
                        memo=memo,
                    )
                ]
                if resolved
            ]
            addresses = {item[0] for item in resolved_inputs}
            if len(addresses) == 1:
                return next(iter(resolved_inputs))
        if mnemonic == "MULTIEQUAL":
            dynamic_inputs = [
                item for item in inputs if not bool(item.get("is_constant"))
            ]
            resolved_inputs = [
                self.resolve_address(
                    item,
                    depth=depth + 1,
                    seen=set(seen),
                    memo=memo,
                )
                for item in dynamic_inputs
            ]
            if (
                dynamic_inputs
                and all(item is not None for item in resolved_inputs)
                and len({item[0] for item in resolved_inputs if item}) == 1
            ):
                address = next(
                    item[0] for item in resolved_inputs if item is not None
                )
                return address, "SSA_MULTIEQUAL_UNANIMOUS"
        if mnemonic in {"INT_ADD", "PTRSUB", "PTRADD"} and inputs:
            constants = [
                _signed_node_constant(item)
                for item in inputs
                if bool(item.get("is_constant"))
            ]
            constants = [item for item in constants if item is not None]
            dynamic_inputs = [
                item for item in inputs if not bool(item.get("is_constant"))
            ]
            resolved_inputs = [
                (
                    item,
                    self.resolve_address(
                        item,
                        depth=depth + 1,
                        seen=set(seen),
                        memo=memo,
                    ),
                )
                for item in dynamic_inputs
            ]
            base_rows = [
                (item, resolved)
                for item, resolved in resolved_inputs
                if resolved is not None
            ]
            unresolved_inputs = [
                item for item, resolved in resolved_inputs if resolved is None
            ]
            if len(base_rows) == 1:
                resolved = base_rows[0][1]
                if unresolved_inputs:
                    # Compilers commonly lower ``array[index].field`` to:
                    #
                    #   scaled = index * record_size
                    #   ptr    = base + scaled
                    #   field  = ptr + constant_field_offset
                    #
                    # Preserve only the stable aggregate base here. The
                    # selector and stride remain explicit in selector_terms;
                    # no runtime index is guessed. Generic dynamic pointer
                    # arithmetic without a recoverable affine term stays
                    # unresolved.
                    selector_terms = _affine_selector_terms(
                        node, self.ops_by_site, self
                    )
                    if (
                        mnemonic in {"INT_ADD", "PTRADD"}
                        and selector_terms
                    ):
                        dynamic_delta = sum(
                            _affine_constant_delta(
                                item, self.ops_by_site
                            )
                            for item in unresolved_inputs
                        )
                        candidate = resolved[0] + dynamic_delta
                        if not in_writable_data(candidate, self.ranges):
                            return None
                        provenance = (
                            "SSA_PTRADD_DYNAMIC_BASE"
                            if mnemonic == "PTRADD"
                            else "SSA_AFFINE_DYNAMIC_BASE"
                        )
                        return candidate, provenance
                    return None
                delta = constants[0] if constants else 0
                if mnemonic == "PTRADD" and len(constants) > 1:
                    delta = constants[0] * constants[1]
                candidate = resolved[0] + delta
                if in_writable_data(candidate, self.ranges):
                    return candidate, f"SSA_{mnemonic}"
        return None

    def writable_block_for_region(
        self, address: int, extent: int
    ) -> dict[str, Any] | None:
        if extent <= 0:
            return None
        end = address + extent - 1
        return next(
            (
                block
                for block in self.writable_blocks
                if int(block["start"]) <= address <= end <= int(block["end"])
            ),
            None,
        )

    def object_for_address(self, address: int) -> dict[str, Any]:
        cached = self._object_cache.get(address)
        if cached is not None:
            return dict(cached)
        block = self.writable_block_for_region(address, 1)
        sized = sorted(
            (
                (start, end, name)
                for start, end, name in self.elf_object_symbols
                if start <= address <= end
            ),
            key=lambda item: (item[1] - item[0], item[0], item[2]),
        )
        if sized:
            base, end, name = sized[0]
            node_id = f"obj:symbol:{base:08x}:{name}"
            result = {
                "node_id": node_id,
                "object_id": node_id,
                "base_object_id": f"obj:ram:{base:08x}",
                "recovered_object_id": f"elf-object:{base:08x}:{name}",
                "name": name,
                "base_address": hex(base),
                "address_range": [hex(base), hex(end)],
                "identity_kind": "ELF_OBJECT_SYMBOL_RANGE",
                "storage_kind": "STATIC_WRITABLE_DATA",
                "writable": block is not None,
                "is_stack": False,
                "is_rom": False,
                "strict_region_eligible": block is not None,
                "memory_block": str((block or {}).get("name", "")),
                "evidence_level": "DETERMINISTIC_IDENTITY",
                "source_evidence_ids": [],
            }
            self._object_cache[address] = result
            return dict(result)
        exact_symbols = sorted(
            (symbol for symbol in self.symbols if symbol[0] == address),
            key=lambda item: (item[1], item[2]),
        )
        if exact_symbols:
            base, name, recovered_object_id = exact_symbols[0]
            node_id = f"obj:symbol:{base:08x}:{name}"
            result = {
                "node_id": node_id,
                "object_id": node_id,
                "base_object_id": f"obj:ram:{base:08x}",
                "recovered_object_id": recovered_object_id,
                "name": name,
                "base_address": hex(base),
                "address_range": [hex(base), hex(base)],
                "identity_kind": "ELF_SYMBOL_EXACT_ADDRESS",
                "storage_kind": "STATIC_WRITABLE_DATA",
                "writable": block is not None,
                "is_stack": False,
                "is_rom": False,
                "strict_region_eligible": block is not None,
                "memory_block": str((block or {}).get("name", "")),
                "evidence_level": "DETERMINISTIC_IDENTITY",
                "source_evidence_ids": [],
            }
            self._object_cache[address] = result
            return dict(result)
        node_id = f"obj:ram:{address:08x}"
        result = {
            "node_id": node_id,
            "object_id": node_id,
            "base_object_id": node_id,
            "name": "",
            "base_address": hex(address),
            "address_range": [hex(address), hex(address)],
            "identity_kind": "EXACT_ADDRESS",
            "storage_kind": "STATIC_WRITABLE_DATA",
            "writable": block is not None,
            "is_stack": False,
            "is_rom": False,
            "strict_region_eligible": block is not None,
            "memory_block": str((block or {}).get("name", "")),
            "evidence_level": "DETERMINISTIC_IDENTITY",
            "source_evidence_ids": [],
        }
        self._object_cache[address] = result
        return dict(result)

    def region_from_node(
        self, node: dict[str, Any], extent: int
    ) -> tuple[str, dict[str, Any], str, dict[str, Any]] | None:
        resolved = self.resolve_address(node)
        if not resolved or extent <= 0:
            return None
        address, provenance = resolved
        return self.region_from_address(address, extent, provenance)

    def region_from_address(
        self, address: int, extent: int, provenance: str
    ) -> tuple[str, dict[str, Any], str, dict[str, Any]] | None:
        block = self.writable_block_for_region(address, extent)
        if block is None:
            return None
        obj = self.object_for_address(address)
        base = parse_int(obj.get("base_address"))
        base_object_id = str(obj.get("base_object_id", ""))
        if base is None or not base_object_id or address < base:
            return None
        offset = address - base
        region_id = stable_region_id(base_object_id, offset, extent)
        region = {
            "region_id": region_id,
            "base_object_id": base_object_id,
            "offset": offset,
            "extent": extent,
            "start": hex(address),
            "end": hex(address + extent - 1),
            "memory_block": str(block.get("name", "")),
            "writable": True,
            "is_stack": False,
            "is_rom": False,
        }
        return str(obj["node_id"]), obj, provenance, region

    def object_from_node(self, node: dict[str, Any]) -> tuple[str, dict[str, Any], str] | None:
        resolved = self.resolve_address(node)
        if not resolved:
            return None
        address, provenance = resolved
        obj = self.object_for_address(address)
        return str(obj["node_id"]), obj, provenance


def _node_identity(node: dict[str, Any]) -> str:
    return str(node.get("value_id", "") or node.get("object_id", ""))


def _signed_node_constant(node: dict[str, Any]) -> int | None:
    value = parse_int(node.get("offset"))
    if value is None:
        return None
    width = max(1, int(node.get("size", 4) or 4)) * 8
    mask = (1 << width) - 1
    value &= mask
    sign = 1 << (width - 1)
    return value - (1 << width) if value & sign else value


def _stack_pointer_offset(
    node: dict[str, Any],
    ops_by_site: dict[str, dict[str, Any]],
    *,
    depth: int = 0,
    seen: set[str] | None = None,
) -> int | None:
    """Recover a stack-local pointer without architecture register guessing."""

    if depth > 12:
        return None
    seen = set(seen or set())
    identity = _node_identity(node)
    if identity and identity in seen:
        return None
    if identity:
        seen.add(identity)
    if str(node.get("space", "")) == "stack":
        text = str(node.get("offset", ""))
        if text.startswith("0x-"):
            return -int(text[3:], 16)
        return _signed_node_constant(node)
    op = ops_by_site.get(str(node.get("def_site_id", "")))
    if not op:
        return None
    mnemonic = str(op.get("mnemonic", ""))
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    if mnemonic in {"COPY", "CAST", "SUBPIECE"}:
        for item in inputs:
            if bool(item.get("is_constant")):
                continue
            resolved = _stack_pointer_offset(
                item, ops_by_site, depth=depth + 1, seen=seen
            )
            if resolved is not None:
                return resolved
    if mnemonic in {"PTRSUB", "PTRADD", "INT_ADD"}:
        constants = [
            _signed_node_constant(item)
            for item in inputs
            if bool(item.get("is_constant"))
        ]
        constants = [value for value in constants if value is not None]
        bases = [item for item in inputs if not bool(item.get("is_constant"))]
        for base in bases:
            base_offset = _stack_pointer_offset(
                base, ops_by_site, depth=depth + 1, seen=seen
            )
            if base_offset is not None:
                return base_offset + (constants[0] if constants else 0)
        # Ghidra represents ``&stack_local`` as PTRSUB(SP, negative_offset).
        # The negative constant itself is sufficient to identify the frame
        # relative location; no ARM-specific SP register number is required.
        if mnemonic == "PTRSUB" and constants and constants[0] < 0:
            return constants[0]
    return None


def _stack_pointer_descriptor(
    node: dict[str, Any],
    ops_by_site: dict[str, dict[str, Any]],
    *,
    depth: int = 0,
    seen: set[str] | None = None,
) -> tuple[int, int] | None:
    """Return ``(local_root, relative_offset)`` for one stack pointer.

    High P-code commonly represents ``&local`` as ``PTRSUB(SP, -off)`` and
    ``&local[n]`` as a later ``PTRADD``.  Keeping the first frame-relative
    offset as the object identity prevents unrelated locals in one stack frame
    from aliasing while preserving byte offsets within an array.
    """

    if depth > 12:
        return None
    seen = set(seen or set())
    identity = _node_identity(node)
    if identity and identity in seen:
        return None
    if identity:
        seen.add(identity)

    if str(node.get("space", "")) == "stack":
        offset = _stack_pointer_offset(node, ops_by_site)
        return (offset, 0) if offset is not None else None

    op = ops_by_site.get(str(node.get("def_site_id", "")))
    if not op:
        return None
    mnemonic = str(op.get("mnemonic", ""))
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    if mnemonic in {"COPY", "CAST", "SUBPIECE", "INDIRECT"}:
        resolved = {
            descriptor
            for item in inputs
            if not bool(item.get("is_constant"))
            for descriptor in [
                _stack_pointer_descriptor(
                    item, ops_by_site, depth=depth + 1, seen=seen
                )
            ]
            if descriptor is not None
        }
        return next(iter(resolved)) if len(resolved) == 1 else None

    if mnemonic in {"PTRSUB", "PTRADD", "INT_ADD"}:
        constants = [
            _signed_node_constant(item)
            for item in inputs
            if bool(item.get("is_constant"))
        ]
        constants = [value for value in constants if value is not None]
        bases = [item for item in inputs if not bool(item.get("is_constant"))]
        for base in bases:
            descriptor = _stack_pointer_descriptor(
                base, ops_by_site, depth=depth + 1, seen=seen
            )
            if descriptor is not None:
                delta = constants[0] if constants else 0
                if mnemonic == "PTRADD" and len(constants) > 1:
                    delta = constants[0] * constants[1]
                return descriptor[0], descriptor[1] + delta
        if mnemonic == "PTRSUB" and constants and constants[0] < 0:
            return constants[0], 0
    return None


def _stack_pointer_name(
    node: dict[str, Any],
    ops_by_site: dict[str, dict[str, Any]],
    *,
    depth: int = 0,
    seen: set[str] | None = None,
) -> str:
    if depth > 12:
        return ""
    seen = set(seen or set())
    identity = _node_identity(node)
    if identity and identity in seen:
        return ""
    if identity:
        seen.add(identity)
    name = str(node.get("high_name", "")).strip()
    if name and name != "UNNAMED":
        return name
    op = ops_by_site.get(str(node.get("def_site_id", "")))
    if not op:
        return ""
    names = {
        candidate
        for item in list(op.get("inputs", []) or [])
        for candidate in [
            _stack_pointer_name(
                dict(item or {}), ops_by_site, depth=depth + 1, seen=seen
            )
        ]
        if candidate
    }
    return next(iter(names)) if len(names) == 1 else ""


def _stack_local_object_id(function_id: str, root_offset: int) -> str:
    sign = "m" if root_offset < 0 else "p"
    return f"obj:stack-local:{function_id}:{sign}{abs(root_offset):x}"


def _canonical_selector_atom(
    node: dict[str, Any], ops_by_site: dict[str, dict[str, Any]], *, depth: int = 0
) -> str:
    if depth > 8:
        return _node_identity(node)
    op = ops_by_site.get(str(node.get("def_site_id", "")))
    if op and str(op.get("mnemonic", "")) in {"COPY", "CAST", "INT_ZEXT", "INT_SEXT"}:
        inputs = [
            dict(item or {})
            for item in list(op.get("inputs", []) or [])
            if not bool(dict(item or {}).get("is_constant"))
        ]
        if len(inputs) == 1:
            return _canonical_selector_atom(inputs[0], ops_by_site, depth=depth + 1)
    return _node_identity(node)


def _affine_constant_delta(
    node: dict[str, Any],
    ops_by_site: dict[str, dict[str, Any]],
    *,
    depth: int = 0,
    seen: set[str] | None = None,
) -> int:
    """Recover only the constant displacement inside one affine term.

    The dynamic selector is intentionally ignored here and remains represented
    by ``_affine_selector_terms``. For example, ``index * 12 + 4`` contributes
    a byte displacement of four without assigning any concrete value to
    ``index``.
    """

    if depth > 12:
        return 0
    seen = set(seen or set())
    identity = _node_identity(node)
    if identity and identity in seen:
        return 0
    if identity:
        seen.add(identity)
    if bool(node.get("is_constant")):
        return int(_signed_node_constant(node) or 0)
    op = ops_by_site.get(str(node.get("def_site_id", "")))
    if not op:
        return 0
    mnemonic = str(op.get("mnemonic", ""))
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    if mnemonic in {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE"}:
        dynamic = [item for item in inputs if not bool(item.get("is_constant"))]
        if len(dynamic) == 1:
            return _affine_constant_delta(
                dynamic[0],
                ops_by_site,
                depth=depth + 1,
                seen=seen,
            )
        return 0
    if mnemonic == "INT_ADD":
        return sum(
            _affine_constant_delta(
                item,
                ops_by_site,
                depth=depth + 1,
                seen=set(seen),
            )
            for item in inputs
        )
    if mnemonic == "PTRSUB" and inputs:
        base_delta = _affine_constant_delta(
            inputs[0],
            ops_by_site,
            depth=depth + 1,
            seen=set(seen),
        )
        trailing = sum(
            _affine_constant_delta(
                item,
                ops_by_site,
                depth=depth + 1,
                seen=set(seen),
            )
            for item in inputs[1:]
        )
        return base_delta + trailing
    # PTRADD constants are element strides, and INT_MULT constants are
    # selector scales. Neither is a byte displacement by itself.
    return 0


def _affine_selector_terms(
    node: dict[str, Any],
    ops_by_site: dict[str, dict[str, Any]],
    resolver: DataObjectResolver,
    *,
    depth: int = 0,
    seen: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Extract normalized ``selector * stride`` evidence from a pointer SSA tree."""

    if depth > 12:
        return []
    seen = set(seen or set())
    identity = _node_identity(node)
    if identity and identity in seen:
        return []
    if identity:
        seen.add(identity)
    op = ops_by_site.get(str(node.get("def_site_id", "")))
    if not op:
        return []
    mnemonic = str(op.get("mnemonic", ""))
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    if mnemonic in {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE"}:
        rows: list[dict[str, Any]] = []
        for item in inputs:
            if not bool(item.get("is_constant")):
                rows.extend(
                    _affine_selector_terms(
                        item, ops_by_site, resolver, depth=depth + 1, seen=seen
                    )
                )
        return rows
    if mnemonic == "INT_MULT":
        constants = [
            _signed_node_constant(item)
            for item in inputs
            if bool(item.get("is_constant"))
        ]
        dynamic = [item for item in inputs if not bool(item.get("is_constant"))]
        if len(constants) == 1 and len(dynamic) == 1 and constants[0] is not None:
            return [
                {
                    "selector_value_id": _canonical_selector_atom(
                        dynamic[0], ops_by_site
                    ),
                    "stride": constants[0],
                }
            ]
    if mnemonic == "PTRADD" and len(inputs) >= 2:
        scale = next(
            (
                _signed_node_constant(item)
                for item in reversed(inputs)
                if bool(item.get("is_constant"))
            ),
            None,
        )
        dynamic = [item for item in inputs[1:] if not bool(item.get("is_constant"))]
        if scale is not None and dynamic:
            return [
                {
                    "selector_value_id": _canonical_selector_atom(
                        dynamic[0], ops_by_site
                    ),
                    "stride": scale,
                }
            ]
    if mnemonic in {"INT_ADD", "PTRADD", "PTRSUB"}:
        rows = []
        resolved_bases = 0
        unresolved_dynamic: list[dict[str, Any]] = []
        for item in inputs:
            if bool(item.get("is_constant")):
                continue
            nested = _affine_selector_terms(
                item, ops_by_site, resolver, depth=depth + 1, seen=seen
            )
            if nested:
                rows.extend(nested)
                continue
            # A pointer recovered through a literal-pool COPY/INDIRECT chain
            # is still the static affine base. Requiring an empty def_site_id
            # incorrectly rejected this common compiler representation.
            if resolver.resolve_address(item) is not None:
                resolved_bases += 1
            else:
                unresolved_dynamic.append(item)
        # ``static_buffer + runtime_byte_offset`` is a stable aggregate
        # identity even though the selected byte is not statically known.
        # Record the selector with stride one and let Region overlap remain
        # heuristic. This does not assign a concrete value to the offset.
        if (
            mnemonic == "INT_ADD"
            and resolved_bases == 1
            and len(unresolved_dynamic) == 1
        ):
            selector = _canonical_selector_atom(
                unresolved_dynamic[0], ops_by_site
            )
            if selector:
                rows.append(
                    {
                        "selector_value_id": selector,
                        "stride": 1,
                    }
                )
        unique = {
            (str(row.get("selector_value_id", "")), int(row.get("stride", 0) or 0)): row
            for row in rows
            if str(row.get("selector_value_id", ""))
        }
        return [unique[key] for key in sorted(unique)]
    return []


def _memory_binding(
    node: dict[str, Any],
    function_id: str,
    extent: int,
    extent_kind: str,
    resolver: DataObjectResolver,
) -> dict[str, Any]:
    resolved = resolver.object_from_node(node)
    if resolved:
        object_id, obj, provenance = resolved
        address = resolver.resolve_address(node)
        base = parse_int(obj.get("base_address"))
        if address and base is not None:
            offset = int(address[0]) - base
            return {
                "atom_id": _node_identity(node),
                "value_id": str(node.get("value_id", "")),
                "value_object_id": str(node.get("object_id", "")),
                "object_id": object_id,
                "base_object_id": str(obj.get("base_object_id", "")),
                "storage_kind": str(obj.get("storage_kind", "")),
                "address_provenance": provenance,
                "region": {
                    "object_id": object_id,
                    "base_object_id": str(obj.get("base_object_id", "")),
                    "offset": offset,
                    "size": extent,
                    "extent": extent,
                    "extent_kind": extent_kind,
                    "selector_terms": _affine_selector_terms(
                        node, resolver.ops_by_site, resolver
                    ),
                },
            }
    stack_descriptor = resolver.stack_descriptor(node, function_id)
    if stack_descriptor is not None:
        stack_root, relative_offset = stack_descriptor
        object_id = _stack_local_object_id(function_id, stack_root)
        return {
            "atom_id": _node_identity(node),
            "value_id": str(node.get("value_id", "")),
            "value_object_id": str(node.get("object_id", "")),
            "object_id": object_id,
            "base_object_id": object_id,
            "storage_kind": "STACK_LOCAL",
            "address_provenance": "HIGH_PCODE_STACK_PTRSUB",
            "region": {
                "object_id": object_id,
                "base_object_id": object_id,
                "offset": relative_offset,
                "size": extent,
                "extent": extent,
                "extent_kind": extent_kind,
                "selector_terms": [],
            },
        }
    return {
        "atom_id": _node_identity(node),
        "value_id": str(node.get("value_id", "")),
        "value_object_id": str(node.get("object_id", "")),
        "object_id": "",
        "base_object_id": "",
        "storage_kind": "UNRESOLVED",
        "address_provenance": "UNRESOLVED_POINTER",
        "region": {},
    }


def _access_field_path(
    address_node: dict[str, Any], binding: dict[str, Any]
) -> list[str]:
    """Preserve record fields while aggregating indexed buffer elements."""

    region = dict(binding.get("region", {}) or {})
    offset = region.get("offset")
    selector_terms = list(region.get("selector_terms", []) or [])
    strides = {
        abs(int(dict(term or {}).get("stride", 0) or 0))
        for term in selector_terms
        if int(dict(term or {}).get("stride", 0) or 0)
    }
    record_strides = {stride for stride in strides if stride > 1}
    if isinstance(offset, int) and record_strides:
        stride = min(record_strides)
        field_offset = offset % stride
        return [f"field_offset:{field_offset}"] if field_offset else []

    data_type = str(address_node.get("high_data_type", "")).lower()
    if isinstance(offset, int) and offset and (
        "struct " in data_type or data_type.startswith("struct")
    ):
        return [f"field_offset:{offset}"]
    return []


def _stack_output_region(
    node: dict[str, Any], function_id: str, resolver: DataObjectResolver
) -> tuple[str, int, int] | None:
    descriptor = resolver.stack_descriptor(node, function_id)
    size = int(node.get("size", 0) or 0)
    if descriptor is None or size <= 0:
        return None
    root, relative = descriptor
    object_id = _stack_local_object_id(function_id, root)
    return object_id, relative, relative + size


def primitive_memory_effects(
    program_facts: dict[str, Any],
    primitive_registry: dict[str, Any],
    resolver: DataObjectResolver,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Model stable primitive-copy calls as local memory definitions.

    This fact layer is independent of Sink Miner output. It reads the same
    versioned primitive ABI summaries, then binds them directly to resolved
    High P-code CALL sites. A call can therefore remain a transform fact even
    when role-aware Sink pruning excludes it as a BFS startpoint.
    """

    specs = {
        str(name): dict(spec or {})
        for name, spec in dict(
            primitive_registry.get("primitive_sinks", {}) or {}
        ).items()
        if str(name)
        and str(dict(spec or {}).get("kind", ""))
        in {
            "primitive_memory_copy",
            "compiler_memory_copy",
            "primitive_bounded_string_copy",
        }
    }
    functions = {
        str(function.get("function_id", "")): dict(function or {})
        for function in list(program_facts.get("functions", []) or [])
        if str(function.get("function_id", ""))
    }
    rows_by_site: dict[str, dict[str, Any]] = {}
    for function_id, function in functions.items():
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                continue
            call = dict(op.get("call", {}) or {})
            target_id = str(call.get("target_function_id", ""))
            if not target_id:
                continue
            target_name = str(
                dict(functions.get(target_id, {}) or {}).get("name", "")
                or call.get("target_function", "")
            )
            spec = specs.get(target_name)
            site_id = str(op.get("site_id", ""))
            if not spec or not site_id:
                continue
            rows_by_site[site_id] = {
                "site_id": site_id,
                "function_id": function_id,
                "callee": target_name,
                "sink_kind": str(spec.get("kind", "")),
                "role_argument_indexes": {
                    role: spec.get(f"{role}_arg")
                    for role in ("dst", "src", "len")
                    if isinstance(spec.get(f"{role}_arg"), int)
                },
            }

    ops_by_site = resolver.ops_by_site
    effects: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for site_id, row in sorted(rows_by_site.items()):
        call_op = ops_by_site.get(site_id)
        if not call_op or str(call_op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
            blockers.append({"site_id": site_id, "reason": "primitive_call_site_not_bound"})
            continue
        actuals = [dict(item or {}) for item in list(call_op.get("inputs", []) or [])[1:]]
        role_indexes = dict(row.get("role_argument_indexes", {}) or {})
        dst_index = role_indexes.get("dst")
        src_index = role_indexes.get("src")
        len_index = role_indexes.get("len")
        if not isinstance(dst_index, int) or not isinstance(src_index, int):
            blockers.append({"site_id": site_id, "reason": "primitive_role_indexes_missing"})
            continue
        if dst_index >= len(actuals) or src_index >= len(actuals):
            blockers.append({"site_id": site_id, "reason": "primitive_role_index_out_of_range"})
            continue
        extent_value: int | None = None
        len_node: dict[str, Any] = {}
        if isinstance(len_index, int) and 0 <= len_index < len(actuals):
            len_node = actuals[len_index]
            if bool(len_node.get("is_constant")):
                extent_value = parse_int(len_node.get("offset"))
        extent = max(1, int(extent_value or 1))
        extent_kind = "CONSTANT" if extent_value and extent_value > 0 else "SYMBOLIC_NONZERO_WITNESS"
        function_id = str(row.get("function_id", ""))
        dst = _memory_binding(
            actuals[dst_index], function_id, extent, extent_kind, resolver
        )
        src = _memory_binding(
            actuals[src_index], function_id, extent, extent_kind, resolver
        )
        instruction = str(call_op.get("instruction_address", ""))
        destination_region = dict(dst.get("region", {}) or {})
        destination_atoms: list[str] = []
        if destination_region and dst.get("storage_kind") == "STACK_LOCAL":
            dst_start = int(destination_region.get("offset", 0) or 0)
            dst_end = dst_start + int(destination_region.get("size", 0) or 0)
            for candidate in ops_by_site.values():
                if (
                    str(candidate.get("instruction_address", "")) != instruction
                    or str(candidate.get("mnemonic", "")) != "INDIRECT"
                ):
                    continue
                output = dict(candidate.get("output", {}) or {})
                output_region = _stack_output_region(output, function_id, resolver)
                if not output_region or output_region[0] != dst.get("object_id"):
                    continue
                if max(dst_start, output_region[1]) < min(dst_end, output_region[2]):
                    destination_atoms.append(_node_identity(output))
        effects.append(
            {
                "effect_id": f"primitive-memory-effect:{site_id}",
                "effect_kind": "PRIMITIVE_MEMORY_COPY",
                "function_id": function_id,
                "site_id": site_id,
                "instruction_address": instruction,
                "callee": str(row.get("callee", "")),
                "destination": dst,
                "source": src,
                "length": {
                    "atom_id": _node_identity(len_node),
                    "value_id": str(len_node.get("value_id", "")),
                    "constant": extent_value,
                },
                "memory_definition_atom_ids": sorted(
                    atom for atom in destination_atoms if atom
                ),
                "effect_precision": (
                    "EXACT_REGION" if extent_kind == "CONSTANT" else "MAY_REGION"
                ),
                "assumptions": (
                    []
                    if extent_kind == "CONSTANT"
                    else ["runtime_copy_length_is_positive"]
                ),
            }
        )
    return effects, blockers


def object_from_varnode(
    node: dict[str, Any], resolver: DataObjectResolver
) -> tuple[str, dict[str, Any], str] | None:
    return resolver.object_from_node(node)


def build_exact_graph(
    program_facts: dict[str, Any], resolver: DataObjectResolver | None = None,
    execution_contexts: dict[str, tuple[set[str], str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    object_nodes: dict[str, dict[str, Any]] = {}
    channel_edges: list[dict[str, Any]] = []
    call_edges: list[dict[str, Any]] = []
    seen_edges: set[str] = set()
    resolver = resolver or DataObjectResolver(program_facts)
    deterministic_contexts = infer_deterministic_execution_contexts(program_facts)
    functions_by_id = {
        str(function.get("function_id", "")): function
        for function in list(program_facts.get("functions", []) or [])
        if str(function.get("function_id", ""))
    }

    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        context_ids, context_provenance = function_context(function, execution_contexts)
        deterministic_ids, deterministic_provenance = deterministic_contexts.get(
            function_id, (set(), "NO_DETERMINISTIC_EXECUTION_CONTEXT")
        )
        deterministic_ids_sorted = sorted(deterministic_ids)
        for op in list(function.get("pcode_ops", []) or []):
            mnemonic = str(op.get("mnemonic", ""))
            site_id = str(op.get("site_id", ""))
            inputs = list(op.get("inputs", []) or [])
            if mnemonic in {"CALL", "CALLIND"}:
                call = dict(op.get("call", {}) or {})
                target_id = str(call.get("target_function_id", ""))
                if not target_id:
                    target_id = f"unknown-call-target:{site_id}"
                edge_id = f"call:{site_id}"
                if edge_id not in seen_edges:
                    seen_edges.add(edge_id)
                    resolved_argument_object_ids = []
                    for argument in inputs[1:]:
                        resolved = object_from_varnode(dict(argument or {}), resolver)
                        resolved_argument_object_ids.append(resolved[0] if resolved else "")
                    target_function = functions_by_id.get(target_id, {})
                    formal_parameters = sorted(
                        list(target_function.get("parameters", []) or []),
                        key=lambda row: int(dict(row or {}).get("index", 0)),
                    )
                    call_edges.append(
                        {
                            "edge_id": edge_id,
                            "src_node_id": function_id,
                            "dst_node_id": target_id,
                            "function_id": function_id,
                            "site_id": site_id,
                            "edge_kind": mnemonic,
                            "resolution": (
                                "DIRECT"
                                if mnemonic == "CALL" and call.get("target_function_id")
                                else "EXACT_INDIRECT_TARGET"
                                if mnemonic == "CALLIND" and call.get("target_function_id")
                                else "UNRESOLVED_INDIRECT"
                            ),
                            "argument_object_ids": list(call.get("argument_object_ids", []) or []),
                            "argument_value_ids": list(call.get("argument_value_ids", []) or []),
                            "argument_atom_ids": list(call.get("argument_atom_ids", []) or []),
                            "resolved_argument_object_ids": resolved_argument_object_ids,
                            "formal_parameter_object_ids": [
                                str(dict(parameter or {}).get("object_id", ""))
                                for parameter in formal_parameters
                            ],
                            "resolution_kind": str(call.get("resolution_kind", "")),
                            "resolution_evidence": list(
                                call.get("resolution_evidence", []) or []
                            ),
                            "deterministic_context_ids": deterministic_ids_sorted,
                            "deterministic_context_provenance": deterministic_provenance,
                        }
                    )
                continue

            if mnemonic == "LOAD" and inputs:
                address_node = dict(inputs[-1] or {})
                value = dict(op.get("output", {}) or {})
                access_width = int(value.get("size", 0) or 0)
                edge_kind = "OBJECT_READ"
                src_is_object = True
            elif mnemonic == "STORE" and len(inputs) >= 2:
                address_node = dict(inputs[-2] or {})
                value = dict(inputs[-1] or {})
                access_width = int(value.get("size", 0) or 0)
                edge_kind = "OBJECT_WRITE"
                src_is_object = False
            else:
                continue
            address_binding = _memory_binding(
                address_node,
                function_id,
                access_width,
                "HIGH_PCODE_CONCRETE_ACCESS",
                resolver,
            )
            region_result = resolver.region_from_node(address_node, access_width)
            if region_result:
                node_id, node, address_provenance, region = region_result
                obj = (node_id, node, address_provenance)
            else:
                obj = object_from_varnode(address_node, resolver)
                region = {}
            if obj is None:
                continue
            node_id, node, address_provenance = obj
            binding_region = dict(address_binding.get("region", {}) or {})
            if binding_region:
                region = {**region, **binding_region}
            object_nodes.setdefault(node_id, node)
            edge_id = f"channel:{edge_kind.lower()}:{site_id}:{node_id}"
            if edge_id in seen_edges:
                continue
            seen_edges.add(edge_id)
            channel_edges.append(
                {
                    "edge_id": edge_id,
                    "src_node_id": node_id if src_is_object else function_id,
                    "dst_node_id": function_id if src_is_object else node_id,
                    "site_id": site_id,
                    "edge_kind": edge_kind,
                    "object_id": node_id,
                    "function_id": function_id,
                    "value_id": str(value.get("value_id", "")),
                    "value_object_id": str(value.get("object_id", "")),
                    "access_width": access_width,
                    "context_id": context_ids[0] if len(context_ids) == 1 else "ctx:multiple",
                    "context_ids": context_ids,
                    "context_provenance": context_provenance,
                    "deterministic_context_id": (
                        deterministic_ids_sorted[0]
                        if len(deterministic_ids_sorted) == 1
                        else ""
                    ),
                    "deterministic_context_ids": deterministic_ids_sorted,
                    "deterministic_context_provenance": deterministic_provenance,
                    "evidence_level": "DETERMINISTIC_ACCESS",
                    "address_provenance": address_provenance,
                    "address_value_id": str(address_node.get("value_id", "")),
                    "address_object_id": str(address_node.get("object_id", "")),
                    "address_high_name": str(address_node.get("high_name", "")),
                    "address_high_data_type": str(
                        address_node.get("high_data_type", "")
                    ),
                    "address_binding": address_binding,
                    "field_path": _access_field_path(
                        address_node, address_binding
                    ),
                    "selector_terms": list(
                        binding_region.get("selector_terms", []) or []
                    ),
                    "region_id": str(region.get("region_id", "")),
                    "base_object_id": str(
                        region.get("base_object_id", node.get("base_object_id", ""))
                    ),
                    "region_offset": region.get("offset"),
                    "region_extent": region.get("extent"),
                    "region_address_range": (
                        [region.get("start"), region.get("end")] if region else []
                    ),
                    "region": region,
                    "candidate_only": True,
                    "traversable": False,
                    "candidate_class": "EXACT_HIGH_PCODE_MEMORY_ACCESS",
                    "analysis_blockers": (
                        [] if region else ["exact_access_region_not_recoverable"]
                    ),
                }
            )
    return list(object_nodes.values()), channel_edges, call_edges


def build_value_object_bindings(
    program_facts: dict[str, Any], resolver: DataObjectResolver
) -> list[dict[str, Any]]:
    """Bind pointer SSA values to writable ELF objects when uniquely resolvable.

    These bindings are alias facts, not producer edges. The backward DFA may use
    them to preserve object identity, but a binding alone must never close a
    Source path.
    """

    bindings: dict[tuple[str, str], dict[str, Any]] = {}
    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        for op in list(function.get("pcode_ops", []) or []):
            nodes = [dict(op.get("output", {}) or {})]
            nodes.extend(dict(item or {}) for item in list(op.get("inputs", []) or []))
            for node in nodes:
                value_id = str(node.get("value_id", ""))
                if not value_id or bool(node.get("is_constant")):
                    continue
                if int(node.get("size", 0) or 0) != 4:
                    continue
                def_op = resolver.ops_by_site.get(str(node.get("def_site_id", "")), {})
                if not bool(node.get("is_address")) and str(def_op.get("mnemonic", "")) not in {
                    "CALL", "COPY", "CAST", "INDIRECT", "INT_ADD", "MULTIEQUAL",
                    "PTRADD", "PTRSUB", "SUBPIECE",
                }:
                    continue
                resolved = resolver.object_from_node(node)
                if resolved:
                    object_id, object_node, provenance = resolved
                    identity_kind = str(object_node.get("identity_kind", ""))
                else:
                    stack = resolver.stack_descriptor(node, function_id)
                    if stack is None:
                        continue
                    object_id = _stack_local_object_id(function_id, stack[0])
                    provenance = "HIGH_PCODE_STACK_LOCAL"
                    identity_kind = "HIGH_PCODE_STACK_LOCAL"
                key = (value_id, object_id)
                bindings[key] = {
                    "value_id": value_id,
                    "value_object_id": str(node.get("object_id", "")),
                    "object_id": object_id,
                    "function_id": function_id,
                    "def_site_id": str(node.get("def_site_id", "")),
                    "identity_kind": identity_kind,
                    "provenance": provenance,
                    "binding_kind": "POINTER_VALUE_TO_OBJECT_ALIAS",
                }
    rows = sorted(bindings.values(), key=lambda row: (row["value_id"], row["object_id"]))
    objects_by_value: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        objects_by_value[str(row["value_id"])].add(str(row["object_id"]))
    # A may-alias set is not a stable ObjectId. Preserve the candidates in the
    # underlying P-code, but do not export an arbitrary first object as fact.
    return [
        row
        for row in rows
        if len(objects_by_value[str(row["value_id"])]) == 1
    ]


def enrich_runtime_object_artifacts(
    program_facts: dict[str, Any],
    resolver: DataObjectResolver,
    call_edges: list[dict[str, Any]],
    primitive_effects: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Attach stack/call-result/access-path identities to existing artifacts."""

    runtime = dataflow_objects.RuntimeObjectIndex(
        program_facts,
        static_object=resolver.object_from_node,
        stack_descriptor=resolver.stack_descriptor,
        stack_object_id=_stack_local_object_id,
    )
    bindings, object_nodes = runtime.export()
    objects_by_atom: dict[str, set[str]] = defaultdict(set)
    binding_by_atom: dict[str, dict[str, Any]] = {}
    for row in bindings:
        atom = str(row.get("atom_id", "") or row.get("value_id", ""))
        object_id = str(row.get("object_id", ""))
        if atom and object_id:
            objects_by_atom[atom].add(object_id)
            binding_by_atom[atom] = row
    binding_by_atom = {
        atom: binding_by_atom[atom]
        for atom, objects in objects_by_atom.items()
        if len(objects) == 1
    }

    for edge in call_edges:
        values = [str(item) for item in list(edge.get("argument_value_ids", []) or [])]
        if not values:
            continue
        existing = list(edge.get("resolved_argument_object_ids", []) or [])
        resolved: list[str] = []
        paths: list[list[str]] = []
        for index, atom in enumerate(values):
            binding = binding_by_atom.get(atom, {})
            fallback = str(existing[index]) if index < len(existing) else ""
            resolved.append(str(binding.get("object_id", "")) or fallback)
            paths.append(list(binding.get("access_path", []) or []))
        edge["resolved_argument_object_ids"] = resolved
        edge["argument_access_paths"] = paths

    for effect in primitive_effects:
        for role in ("destination", "source"):
            payload = dict(effect.get(role, {}) or {})
            atom = str(payload.get("atom_id", "") or payload.get("value_id", ""))
            binding = binding_by_atom.get(atom)
            if not binding:
                continue
            if str(payload.get("storage_kind", "")) in {"", "UNRESOLVED"}:
                payload["object_id"] = str(binding.get("object_id", ""))
                payload["base_object_id"] = str(
                    binding.get("root_object_id", binding.get("object_id", ""))
                )
                payload["storage_kind"] = str(binding.get("storage_kind", ""))
                payload["address_provenance"] = str(binding.get("provenance", ""))
            payload["access_path"] = list(binding.get("access_path", []) or [])
            payload["runtime_object_precision"] = str(binding.get("precision", ""))
            effect[role] = payload
        destination = dict(effect.get("destination", {}) or {})
        if destination.get("object_id"):
            effect["destination_object_id"] = str(destination["object_id"])
            effect["destination_access_path"] = list(
                destination.get("access_path", []) or []
            )
    return bindings, object_nodes


def merge_legacy_objects(
    exact_nodes: list[dict[str, Any]], legacy_graph: dict[str, Any]
) -> list[dict[str, Any]]:
    out = list(exact_nodes)
    seen = {str(node.get("node_id", "")) for node in out}
    for legacy in list(legacy_graph.get("object_nodes", []) or []):
        legacy_id = str(legacy.get("object_id", ""))
        node_id = f"legacy:{legacy_id}"
        if node_id in seen:
            continue
        seen.add(node_id)
        out.append(
            {
                "node_id": node_id,
                "object_id": node_id,
                "legacy_object_id": legacy_id,
                "name": ",".join(str(item) for item in list(legacy.get("members", []) or [])),
                "address_range": list(legacy.get("addr_range", []) or []),
                "identity_kind": "COPPERTRACE_SRAM_CLUSTER_FALLBACK",
                "base_object_id": "",
                "writable": False,
                "is_stack": False,
                "is_rom": False,
                "strict_region_eligible": False,
                "evidence_level": "HEURISTIC_CLUSTER_IDENTITY",
                "source_evidence_ids": [],
                "legacy_facts": legacy,
            }
        )
    return out


def legacy_access_edges(
    legacy_graph: dict[str, Any], program_facts: dict[str, Any]
) -> list[dict[str, Any]]:
    """Expose existing CopperTrace writer/reader evidence as v2 edges.

    These edges deliberately carry no ValueId. They make the cross-context
    communication skeleton queryable without pretending that a 0x100 cluster
    establishes exact value flow.
    """
    _, by_name = function_indexes(program_facts)
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()
    for legacy in list(legacy_graph.get("object_nodes", []) or []):
        object_id = f"legacy:{str(legacy.get('object_id', ''))}"
        for edge_kind, sites, object_is_source in (
            ("OBJECT_WRITE", list(legacy.get("writer_sites", []) or []), False),
            ("OBJECT_READ", list(legacy.get("reader_sites", []) or []), True),
        ):
            for index, site in enumerate(sites):
                function_name = str(site.get("fn", ""))
                function = by_name.get(function_name, {})
                function_id = str(function.get("function_id", ""))
                if not function_id:
                    fn_address = parse_int(site.get("fn_addr")) or 0
                    function_id = f"fn:{fn_address:08x}" if fn_address else f"unknown-fn:{function_name}"
                site_address = parse_int(site.get("site_addr")) or 0
                site_id = (
                    f"legacy-site:{function_id}:{site_address:08x}:{edge_kind.lower()}"
                    if site_address
                    else f"legacy-site:{function_id}:{object_id}:{edge_kind.lower()}:{index}"
                )
                edge_id = f"channel:{edge_kind.lower()}:{site_id}:{object_id}"
                if edge_id in seen:
                    continue
                seen.add(edge_id)
                context = str(site.get("context", "UNKNOWN")).lower()
                context_id = (
                    "ctx:main"
                    if context == "main"
                    else f"ctx:isr:{function_id}"
                    if context == "isr"
                    else f"ctx:task:{function_id}"
                    if context in {"task", "thread", "worker"}
                    else "ctx:unknown"
                )
                edges.append(
                    {
                        "edge_id": edge_id,
                        "src_node_id": object_id if object_is_source else function_id,
                        "dst_node_id": function_id if object_is_source else object_id,
                        "site_id": site_id,
                        "edge_kind": edge_kind,
                        "object_id": object_id,
                        "value_id": "",
                        "value_object_id": "",
                        "access_width": 0,
                        "context_id": context_id,
                        "context_ids": [context_id],
                        "context_provenance": "COPPERTRACE_V1_CONTEXT",
                        "evidence_level": "HEURISTIC_CLUSTER_ACCESS",
                        "analysis_blocker": "missing_exact_value_binding",
                        "analysis_blockers": [
                            "legacy_cluster_has_no_exact_region_identity"
                        ],
                        "candidate_only": True,
                        "traversable": False,
                        "candidate_class": "LEGACY_COPPERTRACE_CLUSTER_ACCESS",
                    }
                )
    return edges


def add_source_overlays(
    object_nodes: list[dict[str, Any]],
    sources: dict[str, Any],
    program_facts: dict[str, Any] | None = None,
    resolver: DataObjectResolver | None = None,
) -> list[dict[str, Any]]:
    by_id = {str(node.get("object_id", "")): node for node in object_nodes}
    program_facts = program_facts or {}
    _, functions_by_name = function_indexes(program_facts)
    execution_contexts = infer_execution_contexts(program_facts) if program_facts else {}
    source_edges: list[dict[str, Any]] = []
    nodes_by_value = {
        str(node.get("value_id", "")): node
        for function in list(program_facts.get("functions", []) or [])
        for op in list(function.get("pcode_ops", []) or [])
        for node in ([dict(op.get("output", {}) or {})] + [dict(item or {}) for item in list(op.get("inputs", []) or [])])
        if str(node.get("value_id", ""))
    }
    for source in source_rows(sources):
        source_id = str(source.get("id", ""))
        for output_index, output in enumerate(source_output_rows(source)):
            output_kind = str(output.get("kind", ""))
            output_role = str(output.get("role", ""))
            # Scalar/event outputs are Source values, not memory objects. The
            # DFA indexes those outputs directly by ValueId.
            if output_kind and output_kind != "memory_object":
                continue
            if output_role and output_role not in {"output_buffer", "memory_output"}:
                continue
            raw_object_id = str(output.get("object_id", ""))
            source_value = str(output.get("value_id", ""))
            candidates = [raw_object_id, f"obj:{raw_object_id}"] if raw_object_id else []
            source_node = nodes_by_value.get(source_value)
            if source_node and resolver is not None:
                resolved = resolver.object_from_node(source_node)
                if resolved:
                    resolved_id, resolved_node, _ = resolved
                    candidates.insert(0, resolved_id)
                    if resolved_id not in by_id:
                        object_nodes.append(resolved_node)
                        by_id[resolved_id] = resolved_node
            if not candidates:
                continue
            node = next((by_id[item] for item in candidates if item in by_id), None)
            if node is None:
                node_id = f"source-object:{raw_object_id}"
                node = {
                    "node_id": node_id,
                    "object_id": node_id,
                    "source_object_id": raw_object_id,
                    "name": str(output.get("expression", "") or source.get("source_buffer", "")),
                    "address_range": [],
                    "identity_kind": "SOURCE_BINDING_OVERLAY",
                    "base_object_id": "",
                    "writable": False,
                    "is_stack": False,
                    "is_rom": False,
                    "strict_region_eligible": False,
                    "evidence_level": str(source.get("evidence_level", "HEURISTIC_STRUCTURAL")),
                    "source_evidence_ids": [],
                }
                object_nodes.append(node)
                by_id[node_id] = node
            evidence = list(node.get("source_evidence_ids", []) or [])
            evidence.append(source_id)
            node["source_evidence_ids"] = sorted({item for item in evidence if item})
            function = functions_by_name.get(str(source.get("function", "")), {})
            function_id = str(function.get("function_id", ""))
            site_id = str(source.get("site_id", ""))
            if not function_id or not site_id:
                continue
            context_ids, context_provenance = function_context(function, execution_contexts)
            source_edges.append(
                {
                    "edge_id": (
                        f"channel:source-write:{source_id}:{output_index}:"
                        f"{site_id}:{node['object_id']}"
                    ),
                    "src_node_id": function_id,
                    "dst_node_id": str(node["object_id"]),
                    "site_id": site_id,
                    "edge_kind": "OBJECT_WRITE",
                    "object_id": str(node["object_id"]),
                    "value_id": source_value,
                    "value_object_id": raw_object_id,
                    "access_width": 0,
                    "context_id": context_ids[0] if len(context_ids) == 1 else "ctx:multiple",
                    "context_ids": context_ids,
                    "context_provenance": context_provenance,
                    "evidence_level": (
                        "DETERMINISTIC_SOURCE_ENDPOINT_WRITE"
                        if source.get("decision") == "ACCEPT_DETERMINISTIC"
                        else "HEURISTIC_SOURCE_ENDPOINT_WRITE"
                    ),
                    "source_id": source_id,
                    "source_output_role": output_role or "output_buffer",
                    "analysis_blockers": [
                        "compatibility_source_overlay_is_not_a_source_definition"
                    ],
                    "candidate_only": True,
                    "traversable": False,
                    "candidate_class": "LEGACY_SOURCE_OVERLAY",
                }
            )
    return source_edges


def deterministic_source_definitions(sources: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the sole strict Source input surface.

    ``source_sites`` and ``confirmed_sources`` remain compatibility evidence,
    but they are not SourceDefinitions and cannot promote a channel write.
    """

    rows = sources.get("source_definitions", [])
    if not isinstance(rows, list):
        return []
    return [
        dict(row or {})
        for row in rows
        if str(dict(row or {}).get("decision", "")) == "ACCEPT_DETERMINISTIC"
        and str(dict(row or {}).get("source_definition_id", ""))
    ]


def _positive_extent(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = int(text, 0)
    except ValueError:
        return None
    return parsed if parsed > 0 else None


def _explicit_source_extent(output: dict[str, Any]) -> int | None:
    region = dict(output.get("region", {}) or {})
    for value in (
        region.get("extent"),
        output.get("region_extent"),
        output.get("write_extent"),
        output.get("byte_extent"),
        output.get("extent"),
    ):
        extent = _positive_extent(value)
        if extent is not None:
            return extent
    return None


def _source_blocker(
    definition: dict[str, Any], output_index: int, reason: str, **evidence: Any
) -> dict[str, Any]:
    proof = dict(definition.get("proof", {}) or {})
    return {
        "source_definition_id": str(definition.get("source_definition_id", "")),
        "source_id": str(definition.get("source_id", "")),
        "function_id": str(definition.get("function_id", "")),
        "site_id": str(definition.get("site_id", "")),
        "output_index": output_index,
        "proof_kind": str(proof.get("kind", "")),
        "reason": reason,
        "evidence": evidence,
    }


def _program_fact_indexes(
    program_facts: dict[str, Any],
) -> tuple[
    dict[tuple[str, str], dict[str, Any]],
    dict[tuple[str, str], list[dict[str, Any]]],
]:
    ops_by_function_site: dict[tuple[str, str], dict[str, Any]] = {}
    nodes_by_function_value: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        for op in list(function.get("pcode_ops", []) or []):
            site_id = str(op.get("site_id", ""))
            if function_id and site_id:
                ops_by_function_site[(function_id, site_id)] = op
            nodes = [dict(op.get("output", {}) or {})]
            nodes.extend(dict(item or {}) for item in list(op.get("inputs", []) or []))
            for node in nodes:
                value_id = str(node.get("value_id", ""))
                if function_id and value_id:
                    nodes_by_function_value[(function_id, value_id)].append(node)
    return ops_by_function_site, nodes_by_function_value


def _add_canonical_object(
    object_nodes: list[dict[str, Any]], node: dict[str, Any]
) -> None:
    node_id = str(node.get("node_id", ""))
    if node_id and all(str(item.get("node_id", "")) != node_id for item in object_nodes):
        object_nodes.append(node)


def _summary_output_region(
    output: dict[str, Any],
    function_id: str,
    resolver: DataObjectResolver,
    nodes_by_function_value: dict[tuple[str, str], list[dict[str, Any]]],
    object_nodes: list[dict[str, Any]],
) -> tuple[str, dict[str, Any], str, dict[str, Any]] | None:
    explicit_extent = _explicit_source_extent(output)
    extent = explicit_extent or 1

    addresses: list[tuple[int, str]] = []
    region = dict(output.get("region", {}) or {})
    concrete_address = parse_int(
        region.get("start", output.get("concrete_address", ""))
    )
    if concrete_address is not None:
        addresses.append((concrete_address, "SOURCE_DEFINITION_CONCRETE_ADDRESS"))

    value_id = str(output.get("value_id", ""))
    resolved_regions: dict[str, tuple[str, dict[str, Any], str, dict[str, Any]]] = {}
    for node in nodes_by_function_value.get((function_id, value_id), []):
        if explicit_extent is not None:
            resolved = resolver.region_from_node(node, extent)
            if resolved:
                resolved_regions[str(resolved[3]["region_id"])] = resolved
                continue
        stack = resolver.stack_descriptor(node, function_id)
        if stack is None:
            continue
        root, relative = stack
        object_id = _stack_local_object_id(function_id, root)
        region_id = stable_region_id(object_id, relative, extent)
        object_node = {
            "node_id": object_id,
            "object_id": object_id,
            "base_object_id": object_id,
            "name": _stack_pointer_name(node, resolver.ops_by_site),
            "identity_kind": "HIGH_PCODE_STACK_LOCAL",
            "storage_kind": "STACK_LOCAL",
            "writable": True,
            "is_stack": True,
            "is_rom": False,
            "strict_region_eligible": False,
            "evidence_level": "DETERMINISTIC_LOCAL_IDENTITY",
            "source_evidence_ids": [],
        }
        stack_region = {
            "region_id": region_id,
            "object_id": object_id,
            "base_object_id": object_id,
            "offset": relative,
            "extent": extent,
            "size": extent,
            "extent_kind": (
                "CONSTANT" if explicit_extent is not None else "SYMBOLIC_NONZERO_WITNESS"
            ),
            "start": f"stack:{root:+#x}:{relative:+#x}",
            "end": f"stack:{root:+#x}:{relative + extent - 1:+#x}",
            "memory_block": "STACK",
            "writable": True,
            "is_stack": True,
            "is_rom": False,
        }
        resolved_regions[region_id] = (
            object_id,
            object_node,
            "HIGH_PCODE_STACK_LOCAL",
            stack_region,
        )

    # A one-byte non-zero witness is sound enough to identify a caller stack
    # object, whose identity is the proof needed for formal-output binding. It
    # is not an exact extent for a global/heap object and must not promote one.
    if explicit_extent is None:
        if len(resolved_regions) != 1:
            return None
        resolved = next(iter(resolved_regions.values()))
        _add_canonical_object(object_nodes, resolved[1])
        return resolved

    raw_object_id = str(output.get("object_id", ""))
    for prefix in ("global:", "obj:ram:"):
        if raw_object_id.startswith(prefix):
            token = raw_object_id[len(prefix):].split(":", 1)[0]
            address = parse_int(token)
            if address is not None:
                addresses.append((address, "SOURCE_DEFINITION_ADDRESS_OBJECT_ID"))
            break

    base_object_id = str(region.get("base_object_id", ""))
    offset = _positive_extent(region.get("offset"))
    if region.get("offset") in {0, "0", "0x0"}:
        offset = 0
    if base_object_id and offset is not None:
        base_node = next(
            (
                node
                for node in object_nodes
                if str(node.get("base_object_id", "")) == base_object_id
            ),
            None,
        )
        base_address = parse_int(dict(base_node or {}).get("base_address"))
        if base_address is not None:
            addresses.append(
                (base_address + offset, "SOURCE_DEFINITION_BASE_OBJECT_OFFSET")
            )

    for address, provenance in addresses:
        resolved = resolver.region_from_address(address, extent, provenance)
        if resolved:
            resolved_regions[str(resolved[3]["region_id"])] = resolved
    if len(resolved_regions) != 1:
        return None
    resolved = next(iter(resolved_regions.values()))
    _add_canonical_object(object_nodes, resolved[1])
    return resolved


def _source_write_from_region(
    definition: dict[str, Any],
    output: dict[str, Any],
    output_index: int,
    function_id: str,
    site_id: str,
    resolved: tuple[str, dict[str, Any], str, dict[str, Any]],
    deterministic_contexts: dict[str, tuple[set[str], str]],
    binding_kind: str,
) -> dict[str, Any]:
    object_id, _, address_provenance, region = resolved
    context_ids, context_provenance = deterministic_contexts.get(
        function_id, (set(), "NO_DETERMINISTIC_EXECUTION_CONTEXT")
    )
    context_ids_sorted = sorted(context_ids)
    definition_id = str(definition.get("source_definition_id", ""))
    return {
        "edge_id": (
            f"source-write-candidate:{definition_id}:{output_index}:"
            f"{site_id}:{region['region_id']}"
        ),
        "src_node_id": function_id,
        "dst_node_id": object_id,
        "function_id": function_id,
        "site_id": site_id,
        "edge_kind": "OBJECT_WRITE",
        "object_id": object_id,
        "value_id": str(output.get("value_id", "")),
        "value_object_id": str(output.get("object_id", "")),
        "access_width": int(region["extent"]),
        "region_id": str(region["region_id"]),
        "base_object_id": str(region["base_object_id"]),
        "region_offset": int(region["offset"]),
        "region_extent": int(region["extent"]),
        "region_address_range": [str(region["start"]), str(region["end"])],
        "region": region,
        "deterministic_context_id": (
            context_ids_sorted[0] if len(context_ids_sorted) == 1 else ""
        ),
        "deterministic_context_ids": context_ids_sorted,
        "deterministic_context_provenance": context_provenance,
        "context_id": context_ids_sorted[0] if len(context_ids_sorted) == 1 else "",
        "context_ids": context_ids_sorted,
        "context_provenance": context_provenance,
        "evidence_level": "DETERMINISTIC_SOURCE_REGION_WRITE",
        "address_provenance": address_provenance,
        "source_definition_id": definition_id,
        "source_id": str(definition.get("source_id", "")),
        "source_output_index": output_index,
        "source_output_role": str(output.get("role", "memory_output")),
        "source_binding_kind": binding_kind,
        "source_proof_kind": str(
            dict(definition.get("proof", {}) or {}).get("kind", "")
        ),
        "candidate_only": True,
        "traversable": False,
        "candidate_class": "DETERMINISTIC_SOURCE_WRITE",
        "analysis_blockers": [],
    }


LOCAL_SOURCE_TRANSPARENT_OPS = {
    "COPY",
    "CAST",
    "INDIRECT",
    "INT_ZEXT",
    "INT_SEXT",
    "SUBPIECE",
}
LOCAL_SOURCE_COMPUTE_OPS = {
    "PIECE",
    "INT_ADD",
    "INT_SUB",
    "INT_MULT",
    "INT_DIV",
    "INT_SDIV",
    "INT_REM",
    "INT_SREM",
    "INT_AND",
    "INT_OR",
    "INT_XOR",
    "INT_LEFT",
    "INT_RIGHT",
    "INT_SRIGHT",
    "INT_EQUAL",
    "INT_NOTEQUAL",
    "INT_LESS",
    "INT_SLESS",
    "INT_LESSEQUAL",
    "INT_SLESSEQUAL",
    "BOOL_NEGATE",
    "BOOL_AND",
    "BOOL_OR",
    "BOOL_XOR",
    "PTRADD",
    "PTRSUB",
}


def _call_actual_nodes(op: dict[str, Any]) -> list[dict[str, Any]]:
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    argument_ids = [
        str(item)
        for item in list(dict(op.get("call", {}) or {}).get("argument_value_ids", []) or [])
        if str(item)
    ]
    if argument_ids:
        by_value = {str(item.get("value_id", "")): item for item in inputs}
        resolved = [by_value[value_id] for value_id in argument_ids if value_id in by_value]
        if len(resolved) == len(argument_ids):
            return resolved
    return inputs[1:] if inputs else []


def forward_source_value_provenance(
    program_facts: dict[str, Any],
    sources: dict[str, Any],
    *,
    max_rounds: int = 32,
) -> tuple[
    dict[tuple[str, str], dict[str, dict[str, Any]]],
    list[dict[str, Any]],
]:
    """Compute a bounded deterministic Source value-provenance fixed point."""

    functions = list(program_facts.get("functions", []) or [])
    by_id = {
        str(function.get("function_id", "")): function
        for function in functions
        if str(function.get("function_id", ""))
    }
    provenance: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    blockers: list[dict[str, Any]] = []
    blocker_keys: set[tuple[str, str, str, str]] = set()

    def add_blocker(
        reason: str,
        function_id: str,
        site_id: str,
        value_id: str,
        **evidence: Any,
    ) -> None:
        key = (reason, function_id, site_id, value_id)
        if key in blocker_keys:
            return
        blocker_keys.add(key)
        blockers.append(
            {
                "reason": reason,
                "function_id": function_id,
                "site_id": site_id,
                "value_id": value_id,
                "evidence": evidence,
            }
        )

    def add_value(
        function_id: str,
        value_id: str,
        definition_id: str,
        parent: dict[str, Any] | None,
        transfer: dict[str, Any],
        output_index: int,
    ) -> bool:
        if not function_id or not value_id or not definition_id:
            return False
        key = (function_id, value_id)
        if definition_id in provenance[key]:
            return False
        parent_transfers = list(dict(parent or {}).get("transfers", []) or [])
        provenance[key][definition_id] = {
            "source_definition_id": definition_id,
            "source_output_index": int(
                dict(parent or {}).get("source_output_index", output_index) or 0
            ),
            "seed_value_id": str(
                dict(parent or {}).get("seed_value_id", value_id)
            ),
            "transfers": (parent_transfers + [transfer])[-64:],
        }
        return True

    for definition in deterministic_source_definitions(sources):
        definition_id = str(definition.get("source_definition_id", ""))
        function_id = str(definition.get("function_id", ""))
        proof_kind = str(dict(definition.get("proof", {}) or {}).get("kind", ""))
        if proof_kind not in {
            "high_pcode_def_use",
            "high_pcode_mmio_value_def_use",
            "high_pcode_function_summary",
            "software_interface_summary_instantiation",
        }:
            for output in list(definition.get("outputs", []) or []):
                output = dict(output or {})
                value_id = str(output.get("value_id", ""))
                if value_id and str(output.get("kind", "")) == "scalar_value":
                    add_blocker(
                        "unsupported_source_definition_value_proof",
                        function_id,
                        str(definition.get("site_id", "")),
                        value_id,
                        source_definition_id=definition_id,
                        proof_kind=proof_kind,
                    )
            continue
        for output_index, output in enumerate(list(definition.get("outputs", []) or [])):
            output = dict(output or {})
            value_id = str(output.get("value_id", ""))
            binding_status = str(output.get("binding_status", ""))
            carries_source_value = (
                str(output.get("kind", "")) == "scalar_value"
                or proof_kind in {"high_pcode_def_use", "high_pcode_mmio_value_def_use"}
            )
            binding_is_explicit = binding_status in {
                "",
                "exact_value",
                "high_pcode_value_bound",
                "exact_call_actual",
                "exact_call_return",
            }
            if carries_source_value and value_id and binding_is_explicit:
                add_value(
                    function_id,
                    value_id,
                    definition_id,
                    None,
                    {
                        "kind": "SOURCE_DEFINITION_OUTPUT",
                        "site_id": str(definition.get("site_id", "")),
                        "proof_kind": proof_kind,
                    },
                    output_index,
                )

    formal_values: dict[tuple[str, int], set[str]] = defaultdict(set)
    for function_id, function in by_id.items():
        object_slot: dict[str, int] = {}
        for ordinal, parameter in enumerate(list(function.get("parameters", []) or [])):
            parameter = dict(parameter or {})
            slot = parameter.get("index", parameter.get("parameter_slot", ordinal))
            if not isinstance(slot, int):
                continue
            object_id = str(parameter.get("object_id", ""))
            if object_id:
                object_slot[object_id] = slot
            value_id = str(parameter.get("value_id", ""))
            if value_id:
                formal_values[(function_id, slot)].add(value_id)
        for op in list(function.get("pcode_ops", []) or []):
            nodes = [dict(op.get("output", {}) or {})]
            nodes.extend(dict(item or {}) for item in list(op.get("inputs", []) or []))
            for item in nodes:
                value_id = str(item.get("value_id", ""))
                slot = item.get("parameter_slot")
                if not isinstance(slot, int):
                    slot = object_slot.get(str(item.get("object_id", "")))
                if isinstance(slot, int) and value_id:
                    formal_values[(function_id, slot)].add(value_id)

    calls_by_target: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    direct_calls: list[tuple[str, dict[str, Any], str]] = []
    for function_id, function in by_id.items():
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALL":
                continue
            target_id = str(dict(op.get("call", {}) or {}).get("target_function_id", ""))
            direct_calls.append((function_id, op, target_id))
            if target_id:
                calls_by_target[target_id].append((function_id, op))

    changed = False
    for round_index in range(max_rounds):
        changed = False
        for function_id, function in by_id.items():
            for op in list(function.get("pcode_ops", []) or []):
                mnemonic = str(op.get("mnemonic", ""))
                output = dict(op.get("output", {}) or {})
                output_value = str(output.get("value_id", ""))
                inputs = [
                    dict(item or {})
                    for item in list(op.get("inputs", []) or [])
                    if not bool(dict(item or {}).get("is_constant"))
                    and str(dict(item or {}).get("value_id", ""))
                ]
                if not output_value or not inputs:
                    continue
                input_rows = [
                    provenance.get((function_id, str(item.get("value_id", ""))), {})
                    for item in inputs
                ]
                source_ids: set[str] = set()
                if mnemonic in LOCAL_SOURCE_TRANSPARENT_OPS:
                    source_ids = {
                        definition_id
                        for rows in input_rows
                        for definition_id in rows
                    }
                elif mnemonic in LOCAL_SOURCE_COMPUTE_OPS | {"MULTIEQUAL"}:
                    if input_rows and all(input_rows):
                        source_ids = set(input_rows[0])
                        for rows in input_rows[1:]:
                            source_ids.intersection_update(rows)
                else:
                    continue
                for definition_id in sorted(source_ids):
                    parent = next(
                        rows[definition_id]
                        for rows in input_rows
                        if definition_id in rows
                    )
                    changed |= add_value(
                        function_id,
                        output_value,
                        definition_id,
                        parent,
                        {
                            "kind": "LOCAL_HIGH_PCODE_DEF_USE",
                            "site_id": str(op.get("site_id", "")),
                            "mnemonic": mnemonic,
                            "input_value_ids": [
                                str(item.get("value_id", "")) for item in inputs
                            ],
                        },
                        int(parent.get("source_output_index", 0) or 0),
                    )

        for caller_id, call_op, target_id in direct_calls:
            actuals = _call_actual_nodes(call_op)
            for slot, actual in enumerate(actuals):
                actual_value = str(actual.get("value_id", ""))
                rows = provenance.get((caller_id, actual_value), {})
                if not rows:
                    continue
                formals = sorted(formal_values.get((target_id, slot), set()))
                if not target_id or target_id not in by_id or not formals:
                    add_blocker(
                        "direct_call_actual_formal_identity_unresolved",
                        caller_id,
                        str(call_op.get("site_id", "")),
                        actual_value,
                        target_function_id=target_id,
                        parameter_slot=slot,
                    )
                    continue
                for formal_value in formals:
                    for definition_id, parent in sorted(rows.items()):
                        changed |= add_value(
                            target_id,
                            formal_value,
                            definition_id,
                            parent,
                            {
                                "kind": "DIRECT_CALL_ACTUAL_FORMAL",
                                "site_id": str(call_op.get("site_id", "")),
                                "caller_function_id": caller_id,
                                "callee_function_id": target_id,
                                "parameter_slot": slot,
                            },
                            int(parent.get("source_output_index", 0) or 0),
                        )

        for callee_id, callers in calls_by_target.items():
            callee = by_id.get(callee_id, {})
            for return_op in list(callee.get("pcode_ops", []) or []):
                if str(return_op.get("mnemonic", "")) != "RETURN":
                    continue
                for returned in list(return_op.get("inputs", []) or [])[1:]:
                    return_value = str(dict(returned or {}).get("value_id", ""))
                    rows = provenance.get((callee_id, return_value), {})
                    if not rows:
                        continue
                    for caller_id, call_op in callers:
                        call_output = str(
                            dict(call_op.get("output", {}) or {}).get("value_id", "")
                        )
                        if not call_output:
                            add_blocker(
                                "direct_return_call_output_missing",
                                caller_id,
                                str(call_op.get("site_id", "")),
                                return_value,
                                callee_function_id=callee_id,
                            )
                            continue
                        for definition_id, parent in sorted(rows.items()):
                            changed |= add_value(
                                caller_id,
                                call_output,
                                definition_id,
                                parent,
                                {
                                    "kind": "DIRECT_CALL_RETURN",
                                    "site_id": str(call_op.get("site_id", "")),
                                    "callee_function_id": callee_id,
                                    "return_site_id": str(return_op.get("site_id", "")),
                                },
                                int(parent.get("source_output_index", 0) or 0),
                            )
        if not changed:
            break
    if changed:
        add_blocker(
            "source_provenance_fixed_point_budget_exhausted",
            "",
            "",
            "",
            max_rounds=max_rounds,
            recovered_values=len(provenance),
        )

    for function_id, function in by_id.items():
        for op in list(function.get("pcode_ops", []) or []):
            mnemonic = str(op.get("mnemonic", ""))
            if mnemonic == "CALLIND":
                for actual in _call_actual_nodes(op):
                    actual_value = str(actual.get("value_id", ""))
                    if provenance.get((function_id, actual_value)):
                        add_blocker(
                            "indirect_call_source_provenance_not_admitted",
                            function_id,
                            str(op.get("site_id", "")),
                            actual_value,
                        )
                continue
            if mnemonic in (
                LOCAL_SOURCE_TRANSPARENT_OPS
                | LOCAL_SOURCE_COMPUTE_OPS
                | {"MULTIEQUAL", "STORE", "LOAD", "CALL", "RETURN"}
            ):
                continue
            output_value = str(dict(op.get("output", {}) or {}).get("value_id", ""))
            if not output_value:
                continue
            derived_inputs = [
                str(dict(item or {}).get("value_id", ""))
                for item in list(op.get("inputs", []) or [])
                if provenance.get(
                    (function_id, str(dict(item or {}).get("value_id", "")))
                )
            ]
            if derived_inputs and not provenance.get((function_id, output_value)):
                add_blocker(
                    "unsupported_local_pcode_provenance_transfer",
                    function_id,
                    str(op.get("site_id", "")),
                    output_value,
                    mnemonic=mnemonic,
                    source_derived_input_value_ids=derived_inputs,
                )
    return dict(provenance), blockers


def _body_copy_summary_rows(sources: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    containers = [sources, dict(sources.get("software_analysis", {}) or {})]
    for container in containers:
        for key in ("body_proved_copy_summaries", "copy_summaries"):
            value = container.get(key, [])
            if isinstance(value, list):
                rows.extend(dict(row or {}) for row in value)
    admitted: dict[str, dict[str, Any]] = {}
    for row in rows:
        proof = dict(row.get("proof", {}) or {})
        proof_kind = str(row.get("proof_kind", proof.get("kind", "")))
        function_id = str(row.get("function_id", ""))
        summary_id = str(row.get("summary_id", row.get("id", "")))
        if (
            function_id
            and summary_id
            and proof_kind
            in {
                "body_proved_copy",
                "body_proved_memory_copy",
                "body_proved_copy_wrapper",
                "direct_wrapper_copy_binding",
            }
        ):
            admitted[summary_id] = {**row, "proof_kind": proof_kind}
    return [admitted[key] for key in sorted(admitted)]


def _summary_slot(row: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = row.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def derive_body_proved_copy_writes(
    program_facts: dict[str, Any],
    sources: dict[str, Any],
    source_writes: list[dict[str, Any]],
    object_nodes: list[dict[str, Any]],
    resolver: DataObjectResolver,
    *,
    max_rounds: int = 16,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Propagate source regions through explicit body-proved copy summaries."""

    summaries = _body_copy_summary_rows(sources)
    if not summaries:
        return [], []
    summaries_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for summary in summaries:
        summaries_by_function[str(summary.get("function_id", ""))].append(summary)
    deterministic_contexts = infer_deterministic_execution_contexts(program_facts)
    definitions = {
        str(row.get("source_definition_id", "")): row
        for row in deterministic_source_definitions(sources)
    }
    positions: dict[tuple[str, str], int] = {}
    direct_calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    exact_store_regions: dict[str, list[tuple[int, str, tuple[str, int, int]]]] = defaultdict(list)
    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        for index, op in enumerate(list(function.get("pcode_ops", []) or [])):
            site_id = str(op.get("site_id", ""))
            positions[(function_id, site_id)] = index
            if str(op.get("mnemonic", "")) == "STORE":
                inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
                if len(inputs) >= 2:
                    extent = int(inputs[-1].get("size", 0) or 0)
                    resolved = resolver.region_from_node(inputs[-2], extent)
                    if resolved:
                        exact_store_regions[function_id].append(
                            (
                                index,
                                site_id,
                                (
                                    str(resolved[3]["base_object_id"]),
                                    int(resolved[3]["offset"]),
                                    int(resolved[3]["offset"])
                                    + int(resolved[3]["extent"]),
                                ),
                            )
                        )
            if str(op.get("mnemonic", "")) != "CALL":
                continue
            target_id = str(dict(op.get("call", {}) or {}).get("target_function_id", ""))
            for summary in summaries_by_function.get(target_id, []):
                direct_calls.append((function_id, op, summary))

    all_writes = list(source_writes)
    added: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = {
        (
            str(write.get("source_definition_id", "")),
            str(write.get("site_id", "")),
            str(write.get("region_id", "")),
        )
        for write in all_writes
    }
    blocker_keys: set[tuple[str, str, str]] = set()

    for _ in range(max_rounds):
        changed = False
        for caller_id, call_op, summary in direct_calls:
            site_id = str(call_op.get("site_id", ""))
            summary_id = str(summary.get("summary_id", summary.get("id", "")))
            actuals = _call_actual_nodes(call_op)
            source_slot = _summary_slot(
                summary,
                "source_parameter_slot",
                "source_slot",
                "input_parameter_slot",
            )
            destination_slot = _summary_slot(
                summary,
                "destination_parameter_slot",
                "destination_slot",
                "output_parameter_slot",
            )
            extent = _positive_extent(
                summary.get("extent", summary.get("write_extent"))
            )
            extent_slot = _summary_slot(
                summary, "size_parameter_slot", "extent_parameter_slot"
            )
            if extent is None and extent_slot is not None and extent_slot < len(actuals):
                extent_node = actuals[extent_slot]
                if bool(extent_node.get("is_constant")):
                    extent = _positive_extent(parse_int(extent_node.get("offset")))
            if (
                source_slot is None
                or destination_slot is None
                or source_slot >= len(actuals)
                or destination_slot >= len(actuals)
            ):
                key = (summary_id, site_id, "body_proved_copy_slots_unresolved")
                if key not in blocker_keys:
                    blocker_keys.add(key)
                    blockers.append(
                        {
                            "function_id": caller_id,
                            "site_id": site_id,
                            "summary_id": summary_id,
                            "reason": "body_proved_copy_slots_unresolved",
                        }
                    )
                continue
            if extent is None:
                key = (summary_id, site_id, "body_proved_copy_extent_unresolved")
                if key not in blocker_keys:
                    blocker_keys.add(key)
                    blockers.append(
                        {
                            "function_id": caller_id,
                            "site_id": site_id,
                            "summary_id": summary_id,
                            "reason": "body_proved_copy_extent_unresolved",
                        }
                    )
                continue
            source_region = resolver.region_from_node(actuals[source_slot], extent)
            destination_region = resolver.region_from_node(
                actuals[destination_slot], extent
            )
            if source_region is None or destination_region is None:
                key = (summary_id, site_id, "body_proved_copy_region_unresolved")
                if key not in blocker_keys:
                    blocker_keys.add(key)
                    blockers.append(
                        {
                            "function_id": caller_id,
                            "site_id": site_id,
                            "summary_id": summary_id,
                            "reason": "body_proved_copy_region_unresolved",
                        }
                    )
                continue
            source_interval = (
                int(source_region[3]["offset"]),
                int(source_region[3]["offset"]) + int(source_region[3]["extent"]),
            )
            call_position = positions.get((caller_id, site_id))
            reaching: list[dict[str, Any]] = []
            for write in all_writes:
                if str(write.get("function_id", "")) != caller_id:
                    continue
                write_position = positions.get(
                    (caller_id, str(write.get("site_id", "")))
                )
                interval = _edge_region_interval(write)
                if (
                    call_position is None
                    or write_position is None
                    or write_position >= call_position
                    or not interval
                    or interval[0] != str(source_region[3]["base_object_id"])
                    or interval[1] > source_interval[0]
                    or interval[2] < source_interval[1]
                ):
                    continue
                reaching.append(write)
            if not reaching:
                continue
            latest_by_definition: dict[str, dict[str, Any]] = {}
            for write in reaching:
                definition_id = str(write.get("source_definition_id", ""))
                prior = latest_by_definition.get(definition_id)
                if prior is None or int(
                    positions.get((caller_id, str(prior.get("site_id", ""))), -1)
                ) < int(
                    positions.get((caller_id, str(write.get("site_id", ""))), -1)
                ):
                    latest_by_definition[definition_id] = write
            safe_reaching: list[dict[str, Any]] = []
            for definition_id, write in sorted(latest_by_definition.items()):
                write_position = positions.get(
                    (caller_id, str(write.get("site_id", "")))
                )
                clobber_sites = [
                    store_site
                    for store_position, store_site, interval in exact_store_regions.get(
                        caller_id, []
                    )
                    if write_position is not None
                    and call_position is not None
                    and write_position < store_position < call_position
                    and interval[0] == str(source_region[3]["base_object_id"])
                    and interval[1] < source_interval[1]
                    and source_interval[0] < interval[2]
                ]
                if clobber_sites:
                    key = (
                        summary_id,
                        site_id,
                        f"body_proved_copy_reaching_write_clobbered:{definition_id}",
                    )
                    if key not in blocker_keys:
                        blocker_keys.add(key)
                        blockers.append(
                            {
                                "source_definition_id": definition_id,
                                "function_id": caller_id,
                                "site_id": site_id,
                                "summary_id": summary_id,
                                "reason": "body_proved_copy_reaching_write_clobbered",
                                "evidence": {
                                    "clobber_store_site_ids": sorted(clobber_sites)
                                },
                            }
                        )
                    continue
                safe_reaching.append(write)
            for write in safe_reaching:
                definition_id = str(write.get("source_definition_id", ""))
                key = (definition_id, site_id, str(destination_region[3]["region_id"]))
                if key in seen:
                    continue
                definition = definitions.get(definition_id, {})
                output_index = int(write.get("source_output_index", 0) or 0)
                outputs = list(definition.get("outputs", []) or [])
                output = (
                    dict(outputs[output_index] or {})
                    if 0 <= output_index < len(outputs)
                    else {}
                )
                candidate = _source_write_from_region(
                    definition,
                    output,
                    output_index,
                    caller_id,
                    site_id,
                    destination_region,
                    deterministic_contexts,
                    "BODY_PROVED_COPY_SUMMARY",
                )
                candidate["source_provenance"] = {
                    "source_definition_id": definition_id,
                    "transfers": list(
                        dict(write.get("source_provenance", {}) or {}).get(
                            "transfers", []
                        )
                    )
                    + [
                        {
                            "kind": "BODY_PROVED_COPY_SUMMARY",
                            "summary_id": summary_id,
                            "site_id": site_id,
                            "source_region_id": str(source_region[3]["region_id"]),
                            "destination_region_id": str(
                                destination_region[3]["region_id"]
                            ),
                        }
                    ],
                }
                added.append(candidate)
                all_writes.append(candidate)
                _add_canonical_object(object_nodes, destination_region[1])
                seen.add(key)
                changed = True
        if not changed:
            break
    else:
        blockers.append(
            {
                "reason": "body_proved_copy_fixed_point_budget_exhausted",
                "max_rounds": max_rounds,
            }
        )
    return added, blockers


def derive_deterministic_source_writes(
    program_facts: dict[str, Any],
    sources: dict[str, Any],
    exact_access_edges: list[dict[str, Any]],
    object_nodes: list[dict[str, Any]],
    resolver: DataObjectResolver,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Promote deterministic SourceDefinition outputs to concrete writes."""

    ops_by_function_site, nodes_by_function_value = _program_fact_indexes(program_facts)
    deterministic_contexts = infer_deterministic_execution_contexts(program_facts)
    exact_writes_by_site: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for edge in exact_access_edges:
        if str(edge.get("edge_kind", "")) == "OBJECT_WRITE":
            exact_writes_by_site[
                (str(edge.get("function_id", "")), str(edge.get("site_id", "")))
            ].append(edge)

    writes: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for definition in deterministic_source_definitions(sources):
        definition_id = str(definition.get("source_definition_id", ""))
        function_id = str(definition.get("function_id", ""))
        definition_site = str(definition.get("site_id", ""))
        proof = dict(definition.get("proof", {}) or {})
        proof_kind = str(proof.get("kind", ""))
        outputs = [dict(output or {}) for output in list(definition.get("outputs", []) or [])]
        memory_outputs = [
            (index, output)
            for index, output in enumerate(outputs)
            if str(output.get("kind", "")) == "memory_object"
        ]
        if not memory_outputs:
            continue

        for output_index, output in memory_outputs:
            output_value = str(output.get("value_id", ""))
            if proof_kind == "high_pcode_profile_dma_binding":
                # A DMA source has no CPU-side RAM STORE to promote here. Its
                # exact destination object is seeded by Source Association.
                continue
            if proof_kind == "high_pcode_def_use":
                store_site = str(proof.get("memory_store_site_id", ""))
                status = str(proof.get("site_binding_status", ""))
                if not store_site:
                    blockers.append(
                        _source_blocker(
                            definition, output_index, "source_def_use_store_site_missing"
                        )
                    )
                    continue
                store_op = ops_by_function_site.get((function_id, store_site))
                if not store_op or str(store_op.get("mnemonic", "")) != "STORE":
                    blockers.append(
                        _source_blocker(
                            definition,
                            output_index,
                            "source_def_use_store_not_present_in_high_pcode",
                            memory_store_site_id=store_site,
                        )
                    )
                    continue
                if status and status != "verified_high_pcode_def_use_site":
                    blockers.append(
                        _source_blocker(
                            definition,
                            output_index,
                            "source_def_use_site_not_verified",
                            site_binding_status=status,
                        )
                    )
                    continue
                proof_value = str(proof.get("mmio_load_value_id", ""))
                if not output_value or (proof_value and proof_value != output_value):
                    blockers.append(
                        _source_blocker(
                            definition,
                            output_index,
                            "source_output_value_does_not_match_def_use_root",
                            output_value_id=output_value,
                            proof_value_id=proof_value,
                        )
                    )
                    continue
                exact_writes = exact_writes_by_site.get((function_id, store_site), [])
                exact_writes = [edge for edge in exact_writes if edge.get("region_id")]
                if len(exact_writes) != 1:
                    blockers.append(
                        _source_blocker(
                            definition,
                            output_index,
                            "source_def_use_store_region_not_unique",
                            memory_store_site_id=store_site,
                            recovered_regions=[
                                str(edge.get("region_id", "")) for edge in exact_writes
                            ],
                        )
                    )
                    continue
                exact = exact_writes[0]
                candidate = dict(exact)
                candidate.update(
                    {
                        "edge_id": (
                            f"source-write-candidate:{definition_id}:{output_index}:"
                            f"{store_site}:{exact['region_id']}"
                        ),
                        "access_edge_id": str(exact.get("edge_id", "")),
                        "stored_value_id": str(exact.get("value_id", "")),
                        "value_id": output_value,
                        "value_object_id": str(output.get("object_id", "")),
                        "source_definition_id": definition_id,
                        "source_id": str(definition.get("source_id", "")),
                        "source_output_index": output_index,
                        "source_output_role": str(
                            output.get("role", "memory_output")
                        ),
                        "source_binding_kind": "HIGH_PCODE_DEF_USE_STORE",
                        "source_proof_kind": proof_kind,
                        "evidence_level": "DETERMINISTIC_SOURCE_REGION_WRITE",
                        "candidate_only": True,
                        "traversable": False,
                        "candidate_class": "DETERMINISTIC_SOURCE_WRITE",
                        "analysis_blockers": [],
                    }
                )
                writes.append(candidate)
                continue

            if proof_kind not in {
                "high_pcode_function_summary",
                "software_interface_summary_instantiation",
            }:
                blockers.append(
                    _source_blocker(
                        definition,
                        output_index,
                        "unsupported_source_definition_memory_proof",
                    )
                )
                continue

            call_site = str(proof.get("call_site_id", definition_site))
            call_op = ops_by_function_site.get((function_id, call_site))
            if not call_op or str(call_op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                blockers.append(
                    _source_blocker(
                        definition,
                        output_index,
                        "source_summary_callsite_not_present_in_high_pcode",
                        call_site_id=call_site,
                    )
                )
                continue
            call = dict(call_op.get("call", {}) or {})
            target_id = str(call.get("target_function_id", ""))
            proof_target_id = str(proof.get("callee_function_id", ""))
            if proof_target_id and target_id != proof_target_id:
                blockers.append(
                    _source_blocker(
                        definition,
                        output_index,
                        "source_summary_callee_identity_mismatch",
                        call_target_function_id=target_id,
                        proof_target_function_id=proof_target_id,
                    )
                )
                continue
            if str(call_op.get("mnemonic", "")) == "CALLIND" and not target_id:
                blockers.append(
                    _source_blocker(
                        definition,
                        output_index,
                        "source_summary_indirect_target_not_exact",
                    )
                )
                continue

            binding_status = str(output.get("binding_status", ""))
            actual_value_ids = {
                str(node.get("value_id", ""))
                for node in _call_actual_nodes(call_op)
                if str(node.get("value_id", ""))
            }
            actual_value_ids.update(
                str(item)
                for item in list(call.get("argument_value_ids", []) or [])
                if str(item)
            )
            return_value_id = str(
                dict(call_op.get("output", {}) or {}).get("value_id", "")
            )
            binding_ok = False
            if proof_kind == "high_pcode_function_summary":
                proof_actual = str(proof.get("actual_value_id", ""))
                bindings = list(proof.get("callee_output_bindings", []) or [])
                binding_ok = bool(
                    bindings
                    and output_value
                    and output_value in actual_value_ids
                    and (not proof_actual or proof_actual == output_value)
                    and binding_status in {"", "high_pcode_value_bound", "exact_call_actual"}
                )
            elif binding_status == "exact_call_actual":
                binding_ok = bool(output_value and output_value in actual_value_ids)
            elif binding_status == "exact_call_return":
                binding_ok = bool(output_value and output_value == return_value_id)
            elif binding_status == "exact_descriptor_access_path":
                binding_ok = bool(
                    output.get("concrete_address")
                    or dict(output.get("region", {}) or {}).get("start")
                    or output_value
                )
            if not binding_ok:
                blockers.append(
                    _source_blocker(
                        definition,
                        output_index,
                        "source_summary_output_binding_not_explicit",
                        binding_status=binding_status,
                        output_value_id=output_value,
                    )
                )
                continue

            resolved = _summary_output_region(
                output,
                function_id,
                resolver,
                nodes_by_function_value,
                object_nodes,
            )
            if resolved is None:
                blockers.append(
                    _source_blocker(
                        definition,
                        output_index,
                        "source_summary_region_or_extent_not_unique",
                        explicit_extent=_explicit_source_extent(output),
                    )
                )
                continue
            writes.append(
                _source_write_from_region(
                    definition,
                    output,
                    output_index,
                    function_id,
                    call_site,
                    resolved,
                    deterministic_contexts,
                    (
                        "DIRECT_ACTUAL_FORMAL_BODY_SUMMARY"
                        if proof_kind == "high_pcode_function_summary"
                        else binding_status.upper()
                    ),
                )
            )

    value_provenance, provenance_blockers = forward_source_value_provenance(
        program_facts, sources
    )
    blockers.extend(provenance_blockers)
    definitions_by_id = {
        str(definition.get("source_definition_id", "")): definition
        for definition in deterministic_source_definitions(sources)
    }
    existing_write_keys = {
        (
            str(edge.get("source_definition_id", "")),
            str(edge.get("site_id", "")),
            str(edge.get("region_id", "")),
        )
        for edge in writes
    }
    exact_write_sites: set[tuple[str, str]] = set()
    for exact in exact_access_edges:
        if str(exact.get("edge_kind", "")) != "OBJECT_WRITE":
            continue
        function_id = str(exact.get("function_id", ""))
        site_id = str(exact.get("site_id", ""))
        exact_write_sites.add((function_id, site_id))
        stored_value = str(exact.get("value_id", ""))
        for definition_id, path in sorted(
            value_provenance.get((function_id, stored_value), {}).items()
        ):
            if not exact.get("region_id"):
                blockers.append(
                    {
                        "source_definition_id": definition_id,
                        "function_id": function_id,
                        "site_id": site_id,
                        "value_id": stored_value,
                        "reason": "source_derived_store_region_unresolved",
                        "evidence": {"source_provenance": path},
                    }
                )
                continue
            key = (definition_id, site_id, str(exact.get("region_id", "")))
            if key in existing_write_keys:
                continue
            definition = definitions_by_id.get(definition_id, {})
            output_index = int(path.get("source_output_index", 0) or 0)
            outputs = list(definition.get("outputs", []) or [])
            output = (
                dict(outputs[output_index] or {})
                if 0 <= output_index < len(outputs)
                else {}
            )
            candidate = dict(exact)
            candidate.update(
                {
                    "edge_id": (
                        f"source-write-candidate:{definition_id}:{output_index}:"
                        f"{site_id}:{exact['region_id']}"
                    ),
                    "access_edge_id": str(exact.get("edge_id", "")),
                    "stored_value_id": stored_value,
                    "value_object_id": str(output.get("object_id", "")),
                    "source_definition_id": definition_id,
                    "source_id": str(definition.get("source_id", "")),
                    "source_output_index": output_index,
                    "source_output_role": str(
                        output.get("role", "source_value")
                    ),
                    "source_binding_kind": "FORWARD_HIGH_PCODE_PROVENANCE",
                    "source_proof_kind": str(
                        dict(definition.get("proof", {}) or {}).get("kind", "")
                    ),
                    "source_provenance": path,
                    "evidence_level": "DETERMINISTIC_SOURCE_REGION_WRITE",
                    "candidate_only": True,
                    "traversable": False,
                    "candidate_class": "DETERMINISTIC_SOURCE_WRITE",
                    "analysis_blockers": [],
                }
            )
            writes.append(candidate)
            existing_write_keys.add(key)

    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "STORE":
                continue
            site_id = str(op.get("site_id", ""))
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            stored_value = str(inputs[-1].get("value_id", "")) if inputs else ""
            rows = value_provenance.get((function_id, stored_value), {})
            if not rows or (function_id, site_id) in exact_write_sites:
                continue
            for definition_id, path in sorted(rows.items()):
                blockers.append(
                    {
                        "source_definition_id": definition_id,
                        "function_id": function_id,
                        "site_id": site_id,
                        "value_id": stored_value,
                        "reason": "source_derived_store_region_unresolved",
                        "evidence": {"source_provenance": path},
                    }
                )

    body_copy_writes, body_copy_blockers = derive_body_proved_copy_writes(
        program_facts, sources, writes, object_nodes, resolver
    )
    writes.extend(body_copy_writes)
    blockers.extend(body_copy_blockers)

    unique = {
        (
            str(edge.get("source_definition_id", "")),
            int(edge.get("source_output_index", 0) or 0),
            str(edge.get("site_id", "")),
            str(edge.get("region_id", "")),
        ): edge
        for edge in writes
    }
    blocker_rows = {
        (
            str(row.get("source_definition_id", "")),
            str(row.get("reason", "")),
            str(row.get("function_id", "")),
            str(row.get("site_id", "")),
            str(row.get("value_id", "")),
            int(row.get("output_index", -1) or -1),
        ): row
        for row in blockers
    }
    return [unique[key] for key in sorted(unique)], [
        blocker_rows[key] for key in sorted(blocker_rows)
    ]


def _region_interval_from_binding(
    binding: dict[str, Any],
) -> tuple[str, int, int, tuple[tuple[str, int], ...]] | None:
    region = dict(binding.get("region", {}) or {})
    object_id = str(region.get("object_id", "") or binding.get("object_id", ""))
    offset = region.get("offset")
    size = region.get("size", region.get("extent"))
    if not object_id or not isinstance(offset, int) or not isinstance(size, int) or size <= 0:
        return None
    selectors = tuple(
        sorted(
            (
                str(dict(term or {}).get("selector_value_id", "")),
                int(dict(term or {}).get("stride", 0) or 0),
            )
            for term in list(region.get("selector_terms", []) or [])
            if str(dict(term or {}).get("selector_value_id", ""))
        )
    )
    return object_id, offset, offset + size, selectors


def build_primitive_source_channels(
    primitive_effect_rows: list[dict[str, Any]],
    sources: dict[str, Any],
    object_nodes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str], list[dict[str, Any]]]:
    """Create Mango-level may-flow edges through persistent copied regions.

    Primitive read/write semantics and pointer-object bindings are body-proved.
    Reaching-write and branch feasibility remain may properties, so the path
    is explicitly reported as heuristic rather than as a vulnerability proof.
    """

    deterministic_source_ids = {
        str(row.get("id", ""))
        for row in source_rows(sources)
        if str(row.get("decision", "")) == "ACCEPT_DETERMINISTIC"
    }
    object_by_id = {
        str(node.get("object_id", node.get("node_id", ""))): node
        for node in object_nodes
    }
    initial_source_objects: dict[str, set[str]] = {}
    for object_id, node in object_by_id.items():
        source_ids = {
            str(item) for item in list(node.get("source_evidence_ids", []) or [])
        }
        source_ids &= deterministic_source_ids
        if source_ids:
            initial_source_objects[object_id] = source_ids

    eligible_effects = [
        effect
        for effect in primitive_effect_rows
        if str(dict(effect.get("source", {}) or {}).get("storage_kind", ""))
        == "STATIC_WRITABLE_DATA"
        and str(dict(effect.get("destination", {}) or {}).get("storage_kind", ""))
        == "STATIC_WRITABLE_DATA"
        and _region_interval_from_binding(dict(effect.get("source", {}) or {}))
        and _region_interval_from_binding(dict(effect.get("destination", {}) or {}))
    ]
    provenance = {key: set(value) for key, value in initial_source_objects.items()}
    writes_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_writes: set[tuple[str, str]] = set()
    derived_objects: set[str] = set()
    for _round in range(max(1, len(eligible_effects) + 1)):
        changed = False
        for effect in eligible_effects:
            source = dict(effect.get("source", {}) or {})
            destination = dict(effect.get("destination", {}) or {})
            src_object = str(source.get("object_id", ""))
            dst_object = str(destination.get("object_id", ""))
            source_ids = provenance.get(src_object, set())
            if not source_ids or not dst_object:
                continue
            key = (dst_object, str(effect.get("effect_id", "")))
            if key not in seen_writes:
                writes_by_object[dst_object].append(effect)
                seen_writes.add(key)
            before = set(provenance.get(dst_object, set()))
            after = before | source_ids
            if after != before:
                provenance[dst_object] = after
                changed = True
                if dst_object not in initial_source_objects:
                    derived_objects.add(dst_object)
        if not changed:
            break

    edges: list[dict[str, Any]] = []
    shared_objects: set[str] = set()
    blockers: list[dict[str, Any]] = []
    for object_id in sorted(derived_objects):
        writes = writes_by_object.get(object_id, [])
        reads = [
            effect
            for effect in eligible_effects
            if str(dict(effect.get("source", {}) or {}).get("object_id", ""))
            == object_id
        ]
        for write in writes:
            write_binding = dict(write.get("destination", {}) or {})
            write_interval = _region_interval_from_binding(write_binding)
            if not write_interval:
                continue
            for read in reads:
                if str(read.get("effect_id", "")) == str(write.get("effect_id", "")):
                    continue
                read_binding = dict(read.get("source", {}) or {})
                read_interval = _region_interval_from_binding(read_binding)
                if not read_interval or write_interval[0] != read_interval[0]:
                    continue
                overlap_start = max(write_interval[1], read_interval[1])
                overlap_end = min(write_interval[2], read_interval[2])
                if overlap_start >= overlap_end:
                    continue
                # Dynamic array accesses are admitted only when normalized
                # selector/stride terms agree. This prevents whole-array
                # aliasing merely because two pointers share a base symbol.
                if write_interval[3] != read_interval[3]:
                    blockers.append(
                        {
                            "reason": "primitive_copy_selector_not_equal",
                            "object_id": object_id,
                            "write_effect_id": str(write.get("effect_id", "")),
                            "read_effect_id": str(read.get("effect_id", "")),
                        }
                    )
                    continue
                shared_objects.add(object_id)
                source_ids = sorted(provenance.get(object_id, set()))
                pair_key = (
                    f"primitive-copy-pair:{write.get('site_id', '')}:"
                    f"{read.get('site_id', '')}:{object_id}:"
                    f"{overlap_start:x}:{overlap_end - overlap_start:x}"
                )
                write_id = f"channel:write:{pair_key}"
                read_id = f"channel:read:{pair_key}"
                region = {
                    "object_id": object_id,
                    "base_object_id": str(write_binding.get("base_object_id", "")),
                    "offset": overlap_start,
                    "size": overlap_end - overlap_start,
                    "extent": overlap_end - overlap_start,
                    "extent_kind": "OVERLAPPING_COPY_WITNESS",
                    "selector_terms": [
                        {"selector_value_id": selector, "stride": stride}
                        for selector, stride in write_interval[3]
                    ],
                }
                common = {
                    "object_id": object_id,
                    "region": region,
                    "analysis_precision": "MAY",
                    "strict_admissible": True,
                    "deterministic": False,
                    "traversable": True,
                    "candidate_only": False,
                    "evidence_level": "BODY_PROVED_PRIMITIVE_COPY_REGION",
                    "alias_proof": "EQUAL_OBJECT_OFFSET_AND_AFFINE_SELECTOR",
                    "source_ids": source_ids,
                    "source_id": source_ids[0] if source_ids else "",
                    "assumptions": [
                        "copy_executes_on_a_feasible_path",
                        "runtime_copy_length_is_positive",
                        "reaching_write_is_not_clobbered",
                    ],
                }
                write_source = dict(write.get("source", {}) or {})
                edges.append(
                    {
                        **common,
                        "edge_id": write_id,
                        "edge_kind": "CHANNEL_WRITE",
                        "legacy_edge_kind": "PRIMITIVE_MEMORY_WRITE",
                        "src_node_id": str(write.get("function_id", "")),
                        "dst_node_id": object_id,
                        "site_id": str(write.get("site_id", "")),
                        "value_atom_id": str(write_source.get("atom_id", "")),
                        "value_id": str(write_source.get("value_id", "")),
                        "value_object_id": str(write_source.get("value_object_id", "")),
                        "paired_edge_ids": [read_id],
                        "primitive_effect_id": str(write.get("effect_id", "")),
                    }
                )
                edges.append(
                    {
                        **common,
                        "edge_id": read_id,
                        "edge_kind": "CHANNEL_READ",
                        "legacy_edge_kind": "PRIMITIVE_MEMORY_READ",
                        "src_node_id": object_id,
                        "dst_node_id": str(read.get("function_id", "")),
                        "site_id": str(read.get("site_id", "")),
                        "value_atom_id": str(read_binding.get("atom_id", "")),
                        "value_id": str(read_binding.get("value_id", "")),
                        "value_object_id": str(read_binding.get("value_object_id", "")),
                        "paired_edge_ids": [write_id],
                        "primitive_effect_id": str(read.get("effect_id", "")),
                    }
                )

    unique_edges = {
        str(edge.get("edge_id", "")): edge
        for edge in edges
        if str(edge.get("edge_id", ""))
    }
    return [unique_edges[key] for key in sorted(unique_edges)], shared_objects, blockers


def _edge_region_interval(edge: dict[str, Any]) -> tuple[str, int, int] | None:
    base_object_id = str(edge.get("base_object_id", ""))
    offset = edge.get("region_offset")
    extent = edge.get("region_extent")
    if (
        not base_object_id
        or not isinstance(offset, int)
        or isinstance(offset, bool)
        or not isinstance(extent, int)
        or isinstance(extent, bool)
        or offset < 0
        or extent <= 0
    ):
        return None
    return base_object_id, offset, offset + extent


def _single_deterministic_context(edge: dict[str, Any]) -> str:
    contexts = sorted(
        {
            str(context)
            for context in list(edge.get("deterministic_context_ids", []) or [])
            if str(context)
        }
    )
    return contexts[0] if len(contexts) == 1 else ""


def build_strict_channel_edges(
    source_writes: list[dict[str, Any]],
    exact_access_edges: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Pair concrete Source writes with overlapping cross-context reads."""

    reads = [
        edge
        for edge in exact_access_edges
        if str(edge.get("edge_kind", "")) == "OBJECT_READ"
    ]
    pairs: list[tuple[dict[str, Any], dict[str, Any], int, int]] = []
    blockers: list[dict[str, Any]] = []
    for write in source_writes:
        write_interval = _edge_region_interval(write)
        write_context = _single_deterministic_context(write)
        base = str(write.get("base_object_id", ""))
        same_base = [read for read in reads if str(read.get("base_object_id", "")) == base]
        overlapping: list[tuple[dict[str, Any], int, int]] = []
        deterministic_overlaps: list[tuple[dict[str, Any], int, int, str]] = []
        if write_interval:
            for read in same_base:
                read_interval = _edge_region_interval(read)
                if not read_interval:
                    continue
                overlap_start = max(write_interval[1], read_interval[1])
                overlap_end = min(write_interval[2], read_interval[2])
                if overlap_start >= overlap_end:
                    continue
                overlapping.append((read, overlap_start, overlap_end))
                read_context = _single_deterministic_context(read)
                if read_context:
                    deterministic_overlaps.append(
                        (read, overlap_start, overlap_end, read_context)
                    )
                if write_context and read_context and write_context != read_context:
                    pairs.append((write, read, overlap_start, overlap_end))
        if any(pair[0] is write for pair in pairs):
            continue
        if not write_interval:
            reason = "source_write_region_not_concrete"
        elif not write_context:
            reason = "source_write_context_not_singleton_deterministic"
        elif not same_base:
            reason = "no_read_for_base_object"
        elif not overlapping:
            reason = "no_overlapping_read_region"
        elif not deterministic_overlaps:
            reason = "overlapping_read_context_not_singleton_deterministic"
        else:
            reason = "overlapping_read_not_in_distinct_deterministic_context"
        blockers.append(
            {
                "source_definition_id": str(write.get("source_definition_id", "")),
                "source_write_candidate_id": str(write.get("edge_id", "")),
                "object_id": str(write.get("object_id", "")),
                "base_object_id": base,
                "region_id": str(write.get("region_id", "")),
                "reason": reason,
                "evidence": {
                    "writer_context_ids": list(
                        write.get("deterministic_context_ids", []) or []
                    ),
                    "same_base_read_edge_ids": [
                        str(read.get("edge_id", "")) for read in same_base
                    ],
                    "overlapping_read_edge_ids": [
                        str(read.get("edge_id", "")) for read, _, _ in overlapping
                    ],
                },
            }
        )

    write_rows: dict[str, dict[str, Any]] = {}
    read_rows: dict[str, dict[str, Any]] = {}
    for write, read, overlap_start, overlap_end in pairs:
        write_id = (
            f"channel:write:{write.get('source_definition_id', '')}:"
            f"{write.get('site_id', '')}:{write.get('region_id', '')}"
        )
        read_id = (
            f"channel:read:{read.get('site_id', '')}:{read.get('region_id', '')}"
        )
        pair_id = f"channel-pair:{write_id}:{read_id}"
        overlap = {
            "pair_id": pair_id,
            "base_object_id": str(write.get("base_object_id", "")),
            "offset": overlap_start,
            "extent": overlap_end - overlap_start,
            "writer_context_id": _single_deterministic_context(write),
            "reader_context_id": _single_deterministic_context(read),
        }

        write_row = write_rows.setdefault(
            write_id,
            {
                **write,
                "edge_id": write_id,
                "edge_kind": "CHANNEL_WRITE",
                "legacy_edge_kind": "OBJECT_WRITE",
                "context_id": _single_deterministic_context(write),
                "context_ids": [_single_deterministic_context(write)],
                "context_provenance": str(
                    write.get("deterministic_context_provenance", "")
                ),
                "strict": True,
                "candidate_only": False,
                "traversable": True,
                "evidence_level": "DETERMINISTIC_CHANNEL_EDGE",
                "paired_edge_ids": [],
                "overlap_evidence": [],
            },
        )
        if read_id not in write_row["paired_edge_ids"]:
            write_row["paired_edge_ids"].append(read_id)
            write_row["overlap_evidence"].append(overlap)

        read_row = read_rows.setdefault(
            read_id,
            {
                **read,
                "edge_id": read_id,
                "edge_kind": "CHANNEL_READ",
                "legacy_edge_kind": "OBJECT_READ",
                "context_id": _single_deterministic_context(read),
                "context_ids": [_single_deterministic_context(read)],
                "context_provenance": str(
                    read.get("deterministic_context_provenance", "")
                ),
                "strict": True,
                "candidate_only": False,
                "traversable": True,
                "evidence_level": "DETERMINISTIC_CHANNEL_EDGE",
                "paired_edge_ids": [],
                "source_definition_ids": [],
                "source_ids": [],
                "overlap_evidence": [],
            },
        )
        if write_id not in read_row["paired_edge_ids"]:
            read_row["paired_edge_ids"].append(write_id)
            read_row["overlap_evidence"].append(overlap)
        definition_id = str(write.get("source_definition_id", ""))
        source_id = str(write.get("source_id", ""))
        if definition_id and definition_id not in read_row["source_definition_ids"]:
            read_row["source_definition_ids"].append(definition_id)
        if source_id and source_id not in read_row["source_ids"]:
            read_row["source_ids"].append(source_id)

    for row in list(write_rows.values()) + list(read_rows.values()):
        row["paired_edge_ids"] = sorted(row["paired_edge_ids"])
        row["overlap_evidence"] = sorted(
            row["overlap_evidence"], key=lambda item: str(item["pair_id"])
        )
        if "source_definition_ids" in row:
            row["source_definition_ids"] = sorted(row["source_definition_ids"])
            row["source_ids"] = sorted(row["source_ids"])
    strict_edges = [write_rows[key] for key in sorted(write_rows)]
    strict_edges.extend(read_rows[key] for key in sorted(read_rows))
    return strict_edges, blockers


def classify_shared_object_candidates(
    object_nodes: list[dict[str, Any]], candidate_edges: list[dict[str, Any]]
) -> None:
    writes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    reads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in candidate_edges:
        object_id = str(edge.get("object_id", ""))
        if edge.get("edge_kind") == "OBJECT_WRITE":
            writes[object_id].append(edge)
        elif edge.get("edge_kind") == "OBJECT_READ":
            reads[object_id].append(edge)
    for node in object_nodes:
        object_id = str(node.get("object_id", ""))
        node["candidate_writer_edge_ids"] = sorted(
            str(edge.get("edge_id", "")) for edge in writes.get(object_id, [])
        )
        node["candidate_reader_edge_ids"] = sorted(
            str(edge.get("edge_id", "")) for edge in reads.get(object_id, [])
        )
        node["shared_object_candidate"] = bool(
            writes.get(object_id) and reads.get(object_id)
        )


def classify_deterministic_shared_objects(
    object_nodes: list[dict[str, Any]],
    strict_edges: list[dict[str, Any]],
    construction_blockers: list[dict[str, Any]],
) -> None:
    writes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    reads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    blockers_by_base: dict[str, list[str]] = defaultdict(list)
    for blocker in construction_blockers:
        base = str(blocker.get("base_object_id", ""))
        reason = str(blocker.get("reason", ""))
        if base and reason:
            blockers_by_base[base].append(reason)
    for edge in strict_edges:
        object_id = str(edge.get("object_id", ""))
        if edge.get("edge_kind") == "CHANNEL_WRITE":
            writes[object_id].append(edge)
        elif edge.get("edge_kind") == "CHANNEL_READ":
            reads[object_id].append(edge)
    for node in object_nodes:
        object_id = str(node.get("object_id", ""))
        base_object_id = str(node.get("base_object_id", ""))
        node_writes = writes.get(object_id, [])
        node_reads = reads.get(object_id, [])
        shared = bool(node_writes and node_reads)
        node["writer_edge_ids"] = sorted(
            str(edge.get("edge_id", "")) for edge in node_writes
        )
        node["reader_edge_ids"] = sorted(
            str(edge.get("edge_id", "")) for edge in node_reads
        )
        node["writer_contexts"] = sorted(
            {_single_deterministic_context(edge) for edge in node_writes}
            - {""}
        )
        node["reader_contexts"] = sorted(
            {_single_deterministic_context(edge) for edge in node_reads}
            - {""}
        )
        node["shared_object"] = shared
        node["strict_shared_object"] = shared
        node["shared_classification"] = (
            "DETERMINISTIC_SOURCE_WRITE_OVERLAPPING_CROSS_CONTEXT_READ"
            if shared
            else "NOT_DETERMINISTIC_SHARED_OBJECT"
        )
        node["shared_evidence_level"] = (
            "DETERMINISTIC_CHANNEL_REGION_EVIDENCE"
            if shared
            else "INSUFFICIENT_DETERMINISTIC_SHARED_OBJECT_EVIDENCE"
        )
        node["shared_limitations"] = ["no_happens_before_or_schedule_proof"] if shared else []
        reasons = sorted(set(blockers_by_base.get(base_object_id, [])))
        if not shared:
            if not bool(node.get("writable")):
                reasons.append("object_not_proved_writable_non_stack_non_rom")
            if not node_writes:
                reasons.append("no_qualified_deterministic_source_write")
            if not node_reads:
                reasons.append("no_qualified_overlapping_cross_context_read")
        node["shared_blockers"] = sorted(set(reasons))


def classify_shared_objects(object_nodes: list[dict[str, Any]], channel_edges: list[dict[str, Any]]) -> None:
    writes: dict[str, list[dict[str, Any]]] = defaultdict(list)
    reads: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in channel_edges:
        object_id = str(edge.get("object_id", ""))
        if edge.get("edge_kind") == "OBJECT_WRITE":
            writes[object_id].append(edge)
        elif edge.get("edge_kind") == "OBJECT_READ":
            reads[object_id].append(edge)
    for node in object_nodes:
        object_id = str(node.get("object_id", ""))
        writer_contexts = {
            str(context)
            for edge in writes.get(object_id, [])
            for context in list(edge.get("context_ids", []) or [edge.get("context_id", "")])
            if str(context) and str(context) != "ctx:unknown"
        }
        reader_contexts = {
            str(context)
            for edge in reads.get(object_id, [])
            for context in list(edge.get("context_ids", []) or [edge.get("context_id", "")])
            if str(context) and str(context) != "ctx:unknown"
        }
        cross_context = any(writer != reader for writer in writer_contexts for reader in reader_contexts)
        node["writer_edge_ids"] = [str(edge.get("edge_id", "")) for edge in writes.get(object_id, [])]
        node["reader_edge_ids"] = [str(edge.get("edge_id", "")) for edge in reads.get(object_id, [])]
        node["writer_contexts"] = sorted(writer_contexts)
        node["reader_contexts"] = sorted(reader_contexts)
        node["shared_object"] = bool(writes.get(object_id) and reads.get(object_id) and cross_context)
        node["shared_object_candidate"] = node["shared_object"]
        node["shared_classification"] = (
            "POTENTIAL_CROSS_CONTEXT_WRITE_READ"
            if node["shared_object"]
            else "NOT_OBSERVED_CROSS_CONTEXT"
        )
        node["shared_evidence_level"] = (
            "STATIC_CONTEXT_ACCESS_CANDIDATE"
            if node["shared_object"]
            else "INSUFFICIENT_SHARED_OBJECT_EVIDENCE"
        )
        node["shared_limitations"] = (
            ["no_temporal_handoff_proof", "context_aliasing_may_overapproximate"]
            if node["shared_object"]
            else []
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--program-facts", required=True, type=Path)
    parser.add_argument("--sources-json", required=True, type=Path)
    # Accepted for CLI compatibility; canonical v4 construction does not read
    # Sink Miner results.
    parser.add_argument("--sinks-json", type=Path)
    parser.add_argument(
        "--primitive-registry",
        default=DEFAULT_PRIMITIVE_REGISTRY,
        type=Path,
    )
    parser.add_argument("--elf", type=Path)
    parser.add_argument(
        "--max-finite-callind-targets",
        type=int,
        default=device_dispatch_resolver.DEFAULT_MAX_FINITE_CALLIND_TARGETS,
        help=(
            "Maximum complete target set materialized for one immutable "
            "function-table CALLIND. Over-budget sets remain blockers and "
            "are never truncated."
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    program_facts = read_json(args.program_facts)
    sources = read_json(args.sources_json)
    primitive_registry = sink_artifact_schema.load_sink_registry(
        args.primitive_registry
    )
    dispatch_resolution: dict[str, Any] = {
        "counts": {"callind": 0, "resolved": 0, "ambiguous": 0, "unresolved": 0},
        "resolved": [],
    }
    applied_dispatch_targets = 0
    initialized_memory: device_dispatch_resolver.InitializedMemory | None = None
    if args.elf:
        expected_hash = str(program_facts.get("binary_sha256", ""))
        if expected_hash and sha256_path(args.elf) != expected_hash:
            raise SystemExit("program facts binary_sha256 does not match --elf")
        initialized_memory = device_dispatch_resolver.InitializedMemory.from_elf(
            args.elf
        )
        dispatch_resolution = device_dispatch_resolver.resolve_device_dispatches(
            program_facts,
            initialized_memory=initialized_memory,
            max_finite_callind_targets=max(
                0, int(args.max_finite_callind_targets)
            ),
        )
        applied_dispatch_targets = apply_resolved_dispatch_targets(
            program_facts, dispatch_resolution
        )
    resolver = DataObjectResolver(program_facts)
    execution_contexts = infer_execution_contexts(program_facts)
    mai, memory_map = program_facts_to_mai(program_facts, resolver)
    legacy = build_channel_graph(
        mai,
        sourceagent_label_rows(sources),
        memory_map,
        top_k=64,
        binary_sha256=str(program_facts.get("binary_sha256", "")),
    )
    exact_nodes, exact_channel_edges, call_edges = build_exact_graph(
        program_facts, resolver, execution_contexts
    )
    finite_dispatch_edges, finite_dispatch_blockers = (
        materialize_finite_dispatch_call_edges(
            program_facts, dispatch_resolution, resolver
        )
    )
    finite_dispatch_sites = {
        str(edge.get("site_id", "")) for edge in finite_dispatch_edges
    }
    if finite_dispatch_sites:
        call_edges = [
            edge
            for edge in call_edges
            if not (
                str(edge.get("site_id", "")) in finite_dispatch_sites
                and str(edge.get("resolution", ""))
                == "UNRESOLVED_INDIRECT"
            )
        ]
        call_edges.extend(finite_dispatch_edges)
    value_object_bindings = build_value_object_bindings(program_facts, resolver)
    object_nodes = merge_legacy_objects(exact_nodes, legacy)
    legacy_channel_edges = legacy_access_edges(legacy, program_facts)
    source_overlay_edges = add_source_overlays(
        object_nodes, sources, program_facts, resolver
    )
    primitive_effect_rows, primitive_effect_blockers = primitive_memory_effects(
        program_facts, primitive_registry, resolver
    )
    runtime_bindings, runtime_object_nodes = enrich_runtime_object_artifacts(
        program_facts, resolver, call_edges, primitive_effect_rows
    )
    value_object_bindings.extend(runtime_bindings)
    for runtime_node in runtime_object_nodes:
        _add_canonical_object(object_nodes, runtime_node)
    runtime_index = dataflow_objects.RuntimeObjectIndex(
        program_facts,
        static_object=resolver.object_from_node,
        stack_descriptor=resolver.stack_descriptor,
        stack_object_id=_stack_local_object_id,
    )
    access_fact_index = memory_access_facts.MemoryAccessFactIndex.from_exact_edges(
        exact_channel_edges, object_nodes
    )
    preliminary_output_effects, _preliminary_output_blockers = bind_fixed_output_effects(
        program_facts, call_edges, value_object_bindings
    )
    runtime_callback_resolution = (
        runtime_callback_resolver.resolve_runtime_callback_relations(
            program_facts,
            call_edges,
            runtime=runtime_index,
            access_index=access_fact_index,
            literal_words=resolver.literal_words,
            output_effects=preliminary_output_effects,
            max_wrapper_depth=8,
            max_targets=16,
        )
    )
    runtime_callback_edges = list(
        runtime_callback_resolution.get("call_edges", []) or []
    )
    runtime_callback_sites = {
        str(edge.get("site_id", ""))
        for edge in runtime_callback_edges
        if str(edge.get("site_id", ""))
    }
    if runtime_callback_sites:
        call_edges = [
            edge
            for edge in call_edges
            if str(edge.get("site_id", "")) not in runtime_callback_sites
        ]
        call_edges.extend(runtime_callback_edges)
    call_output_effects, call_output_blockers = bind_fixed_output_effects(
        program_facts, call_edges, value_object_bindings
    )
    bounded_container_aliases = container_alias_resolver.build_bounded_container_aliases(
        program_facts
    )
    (
        deferred_channel_nodes,
        deferred_channel_edges,
        deferred_channel_blockers,
    ) = ccc_effect_resolver.build_deferred_callback_channels(
        program_facts,
        runtime=runtime_index,
        literal_words=resolver.literal_words,
    )
    source_write_candidates, source_write_blockers = derive_deterministic_source_writes(
        program_facts, sources, exact_channel_edges, object_nodes, resolver
    )
    strict_channel_edges, channel_pairing_blockers = build_strict_channel_edges(
        source_write_candidates, exact_channel_edges
    )
    (
        primitive_channel_edges,
        primitive_shared_object_ids,
        primitive_channel_blockers,
    ) = build_primitive_source_channels(
        primitive_effect_rows, sources, object_nodes
    )
    value_provenance, value_provenance_blockers = forward_source_value_provenance(
        program_facts, sources
    )
    (
        object_reference_summaries,
        object_reference_body_blockers,
    ) = object_reference_ccc.recover_body_effect_summaries(program_facts)
    deterministic_contexts = infer_deterministic_execution_contexts(
        program_facts
    )
    source_associations: list[dict[str, Any]] = []
    source_association_blockers: list[dict[str, Any]] = []
    optional_summary_blockers: list[dict[str, Any]] = []
    optional_callback_targets_applied = 0
    association_seeds: list[dict[str, Any]] = []
    previous_signature: tuple[tuple[str, ...], tuple[str, ...]] | None = None
    shared_object_result: dict[str, list[dict[str, Any]]] = {
        "shared_objects": [],
        "rejected_candidates": [],
        "blockers": [],
    }
    source_associated_transport_result: dict[str, list[dict[str, Any]]] = {
        "shared_objects": [],
        "rejected_candidates": [],
        "blockers": [],
    }
    source_centric_channel_edges: list[dict[str, Any]] = []
    object_reference_writers: list[dict[str, Any]] = []
    object_reference_readers: list[dict[str, Any]] = []
    object_reference_binding_blockers: list[dict[str, Any]] = []
    object_reference_shared_result: dict[str, list[dict[str, Any]]] = {
        "shared_objects": [],
        "rejected_candidates": [],
        "blockers": [],
    }
    for association_round in range(9):
        (
            source_associations,
            round_association_blockers,
        ) = source_association.build_source_associations(
            program_facts,
            sources,
            value_provenance=value_provenance,
            channel_edges=primitive_channel_edges + strict_channel_edges,
            runtime=runtime_index,
            seed_associations=association_seeds,
            access_index=access_fact_index,
            primitive_memory_effects=primitive_effect_rows,
            call_output_effects=call_output_effects,
            call_edges=call_edges,
            max_channel_depth=8,
        )
        source_association_blockers.extend(round_association_blockers)
        concrete_shared_object_result = (
            shared_object_miner.mine_source_associated_shared_objects(
                access_fact_index, source_associations
            )
        )
        source_associated_transport_result = (
            shared_object_miner.mine_source_associated_transport_objects(
                deferred_channel_nodes,
                deferred_channel_edges,
                source_associations,
            )
        )
        (
            object_reference_writers,
            object_reference_readers,
            round_object_reference_blockers,
        ) = object_reference_ccc.instantiate_callsites(
            program_facts,
            object_reference_summaries,
            source_associations=source_associations,
            runtime=runtime_index,
        )
        object_reference_binding_blockers.extend(
            round_object_reference_blockers
        )
        object_reference_shared_result = (
            shared_object_miner.mine_object_reference_effect_objects(
                object_reference_writers,
                object_reference_readers,
                source_associations,
                deterministic_contexts=deterministic_contexts,
            )
        )
        merged_shared_object_result = shared_object_miner.mine_shared_objects(
            list(
                concrete_shared_object_result.get("shared_objects", [])
                or []
            )
            + list(
                source_associated_transport_result.get(
                    "shared_objects", []
                )
                or []
            )
            + list(
                object_reference_shared_result.get("shared_objects", [])
                or []
            )
        )
        shared_object_result = {
            "shared_objects": list(
                merged_shared_object_result.get("shared_objects", []) or []
            ),
            "rejected_candidates": (
                list(
                    concrete_shared_object_result.get(
                        "rejected_candidates", []
                    )
                    or []
                )
                + list(
                    source_associated_transport_result.get(
                        "rejected_candidates", []
                    )
                    or []
                )
                + list(
                    merged_shared_object_result.get(
                        "rejected_candidates", []
                    )
                    or []
                )
                + list(
                    object_reference_shared_result.get(
                        "rejected_candidates", []
                    )
                    or []
                )
            ),
            "blockers": (
                list(
                    concrete_shared_object_result.get("blockers", []) or []
                )
                + list(
                    source_associated_transport_result.get(
                        "blockers", []
                    )
                    or []
                )
                + list(
                    merged_shared_object_result.get("blockers", []) or []
                )
                + list(
                    object_reference_shared_result.get("blockers", []) or []
                )
            ),
        }
        source_centric_channel_edges = (
            shared_object_miner.materialize_channel_edges(
                list(shared_object_result.get("shared_objects", []) or [])
            )
        )

        # Optional body summaries may resolve a concrete callback target, but
        # they do not create or admit the shared-object itself.
        (
            round_event_candidates,
            round_event_blockers,
        ) = ccc_effect_resolver.build_event_queue_candidates(
            program_facts,
            runtime=runtime_index,
            literal_words=resolver.literal_words,
            exact_access_edges=exact_channel_edges,
            source_associations=source_associations,
        )
        optional_summary_blockers.extend(round_event_blockers)
        applied_targets, target_blockers = apply_body_proved_callback_targets(
            program_facts, call_edges, round_event_candidates
        )
        optional_callback_targets_applied += applied_targets
        optional_summary_blockers.extend(target_blockers)
        signature = (
            tuple(
                sorted(
                    str(row.get("association_id", ""))
                    for row in source_associations
                )
            ),
            tuple(
                sorted(
                    str(edge.get("edge_id", ""))
                    for edge in source_centric_channel_edges
                )
            ),
        )
        if signature == previous_signature:
            break
        previous_signature = signature
        association_seeds = source_association.channel_relation_seeds(
            source_centric_channel_edges
        )
    else:
        source_association_blockers.append(
            {
                "reason": "source_association_channel_fixed_point_budget_exhausted",
                "evidence": {
                    "max_rounds": 8,
                    "association_count": len(source_associations),
                    "source_centric_channel_edges": len(
                        source_centric_channel_edges
                    ),
                },
            }
        )
    normalized_source_centric_edges = [
        normalize_channel_edge_v4(edge)
        for edge in source_centric_channel_edges
    ]
    invalid_normalized_edges = [
        edge
        for edge in normalized_source_centric_edges
        if not bool(edge.get("traversable"))
    ]
    channel_edges = sorted(
        (
            edge
            for edge in normalized_source_centric_edges
            if bool(edge.get("traversable"))
        ),
        key=lambda edge: str(edge.get("edge_id", "")),
    )
    candidate_channel_edges = sorted(
        exact_channel_edges
        + legacy_channel_edges
        + source_overlay_edges
        + source_write_candidates,
        key=lambda edge: str(edge.get("edge_id", "")),
    )
    channel_blockers = (
        source_write_blockers
        + channel_pairing_blockers
        + primitive_effect_blockers
        + finite_dispatch_blockers
        + call_output_blockers
        + primitive_channel_blockers
        + deferred_channel_blockers
        + value_provenance_blockers
        + source_association_blockers
        + optional_summary_blockers
        + object_reference_body_blockers
        + object_reference_binding_blockers
        + list(shared_object_result.get("blockers", []) or [])
        + [
            {
                "reason": str(
                    list(edge.get("analysis_blockers", []) or [])[-1]
                ),
                "site_id": str(edge.get("site_id", "")),
                "object_id": str(edge.get("object_id", "")),
                "edge_id": str(edge.get("edge_id", "")),
            }
            for edge in invalid_normalized_edges
            if list(edge.get("analysis_blockers", []) or [])
        ]
    )
    channel_blockers = [
        json.loads(key)
        for key in sorted(
            {
                json.dumps(dict(row or {}), sort_keys=True)
                for row in channel_blockers
            }
        )
    ]
    if not deterministic_source_definitions(sources):
        channel_blockers.append(
            {
                "reason": "no_deterministic_source_definitions",
                "evidence": {
                    "source_definition_count": len(
                        list(sources.get("source_definitions", []) or [])
                    )
                },
            }
        )
    classify_shared_object_candidates(object_nodes, candidate_channel_edges)
    source_centric_shared_by_object = {
        str(row.get("object_id", "")): row
        for row in list(shared_object_result.get("shared_objects", []) or [])
        if str(row.get("object_id", ""))
    }
    existing_object_ids = {
        str(node.get("object_id", node.get("node_id", "")))
        for node in object_nodes
    }
    for object_id, shared in source_centric_shared_by_object.items():
        if object_id in existing_object_ids:
            continue
        object_nodes.append(
            {
                "node_id": object_id,
                "object_id": object_id,
                "base_object_id": str(shared.get("base_object_id", object_id)),
                "name": "",
                "identity_kind": "NORMALIZED_SHARED_OBJECT_REGION",
                "storage_kind": str(
                    shared.get("storage_kind", "STATIC_WRITABLE_DATA")
                ),
                "writable": True,
                "is_stack": False,
                "is_rom": False,
                "strict_region_eligible": True,
                "evidence_level": str(shared.get("evidence_level", "")),
                "source_evidence_ids": list(shared.get("source_ids", []) or []),
            }
        )
    for node in object_nodes:
        object_id = str(node.get("object_id", node.get("node_id", "")))
        shared = source_centric_shared_by_object.get(object_id)
        if shared is None:
            continue
        node["shared_object"] = True
        node["shared_object_candidate"] = True
        node["strict_shared_object"] = (
            str(shared.get("recognition", "")) == "deterministic"
        )
        node["shared_classification"] = (
            "SOURCE_ASSOCIATED_CONCRETE_STORE_LOAD"
        )
        node["shared_evidence_level"] = str(
            shared.get(
                "evidence_level",
                "SOURCE_ASSOCIATED_CONCRETE_STORE_LOAD",
            )
        )
        node["shared_limitations"] = (
            []
            if node["strict_shared_object"]
            else ["relation_is_heuristic"]
        )
        node["shared_blockers"] = []
        node["source_evidence_ids"] = sorted(
            {
                *list(node.get("source_evidence_ids", []) or []),
                *list(shared.get("source_ids", []) or []),
            }
        )
    function_nodes = []
    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        context_ids, provenance = function_context(function, execution_contexts)
        deterministic_ids, deterministic_provenance = deterministic_contexts.get(
            function_id, (set(), "NO_DETERMINISTIC_EXECUTION_CONTEXT")
        )
        deterministic_ids_sorted = sorted(deterministic_ids)
        function_nodes.append(
            {
                "node_id": function_id,
                "node_kind": "FUNCTION",
                "name": str(function.get("name", "")),
                "entry": str(function.get("entry", "")),
                "context_id": context_ids[0] if len(context_ids) == 1 else "ctx:multiple",
                "context_ids": context_ids,
                "context_provenance": provenance,
                "deterministic_context_id": (
                    deterministic_ids_sorted[0]
                    if len(deterministic_ids_sorted) == 1
                    else ""
                ),
                "deterministic_context_ids": deterministic_ids_sorted,
                "deterministic_context_provenance": deterministic_provenance,
                "context_blockers": (
                    []
                    if len(deterministic_ids_sorted) == 1
                    else [
                        "execution_context_not_recovered"
                        if not deterministic_ids_sorted
                        else "execution_context_not_unique"
                    ]
                ),
            }
        )

    strict_object_ids = {
        str(edge.get("object_id", ""))
        for edge in channel_edges
        if str(edge.get("object_id", ""))
    }
    unified_object_nodes = [
        {**node, "node_kind": "SHARED_OBJECT"}
        for node in object_nodes
        if str(node.get("object_id", node.get("node_id", ""))) in strict_object_ids
        and bool(node.get("shared_object"))
    ]
    unified_function_nodes = [
        {**node, "node_kind": "FUNCTION"} for node in function_nodes
    ]
    unified_nodes = sorted(
        unified_function_nodes + unified_object_nodes,
        key=lambda node: str(node.get("node_id", "")),
    )
    unified_edges = sorted(
        call_edges + channel_edges,
        key=lambda edge: str(edge.get("edge_id", "")),
    )

    artifact = {
        "schema_version": "ct-mini-channel-graph-v4",
        "binary": str(program_facts.get("binary", "")),
        "binary_sha256": str(program_facts.get("binary_sha256", "")),
        "construction": "source_associated_concrete_store_load_channels",
        "canonical_sink_input_used": False,
        "primitive_summary_registry": {
            "path": str(args.primitive_registry),
            "sha256": sha256_path(args.primitive_registry),
        },
        "strict_traversal_surface": "channel_edges",
        "dispatch_resolution": {
            "counts": dict(dispatch_resolution.get("counts", {}) or {}),
            "applied_unique_targets": applied_dispatch_targets,
            "finite_may_call_edges": len(finite_dispatch_edges),
        },
        "runtime_callback_resolution": runtime_callback_resolution,
        "function_nodes": function_nodes,
        "object_nodes": object_nodes,
        # Canonical analysis surface. Candidate objects/accesses remain in the
        # compatibility arrays below, but only these nodes and edges may be
        # traversed by the strict sink-backward analysis.
        "nodes": unified_nodes,
        "edges": unified_edges,
        "call_edges": sorted(call_edges, key=lambda edge: str(edge.get("edge_id", ""))),
        "channel_edges": sorted(
            channel_edges, key=lambda edge: str(edge.get("edge_id", ""))
        ),
        "source_associations": source_associations,
        "shared_objects": list(
            shared_object_result.get("shared_objects", []) or []
        ),
        "source_associated_transport_objects": list(
            source_associated_transport_result.get("shared_objects", []) or []
        ),
        "rejected_shared_object_candidates": list(
            shared_object_result.get("rejected_candidates", []) or []
        ),
        "primitive_memory_effects": primitive_effect_rows,
        "call_output_effects": call_output_effects,
        "object_reference_effects": {
            "body_effect_summaries": object_reference_summaries,
            "writer_facts": object_reference_writers,
            "reader_facts": object_reference_readers,
        },
        "compatibility_relations": {
            "strict_v3_channel_edges": strict_channel_edges,
            "primitive_copy_relations": primitive_channel_edges,
            "deferred_callback_relations": deferred_channel_edges,
            "canonical_traversal": False,
        },
        "deferred_callback_channels": deferred_channel_edges,
        "optional_callback_target_summaries": {
            "applied_targets": optional_callback_targets_applied,
            "canonical_shared_object_admission": False,
        },
        "bounded_container_aliases": bounded_container_aliases,
        "memory_access_facts": access_fact_index.debug_dict(),
        "candidate_channel_edges": candidate_channel_edges,
        "channel_blockers": channel_blockers,
        "value_object_bindings": value_object_bindings,
        "counts": {
            "function_nodes": len(function_nodes),
            "object_nodes": len(object_nodes),
            "shared_objects": len([node for node in object_nodes if node.get("shared_object")]),
            "unified_nodes": len(unified_nodes),
            "unified_edges": len(unified_edges),
            "unified_shared_object_nodes": len(unified_object_nodes),
            "call_edges": len(call_edges),
            "resolved_indirect_call_edges": len(
                [
                    edge
                    for edge in call_edges
                    if edge.get("edge_kind") == "CALLIND"
                    and edge.get("resolution") == "EXACT_INDIRECT_TARGET"
                ]
            ),
            "finite_may_call_edges": len(finite_dispatch_edges),
            "runtime_callback_call_edges": len(runtime_callback_edges),
            "channel_edges": len(channel_edges),
            "strict_channel_edges": len(strict_channel_edges),
            "mango_level_primitive_channel_edges": len(primitive_channel_edges),
            "primitive_memory_effects": len(primitive_effect_rows),
            "call_output_effects": len(call_output_effects),
            "object_reference_body_effect_summaries": len(
                object_reference_summaries
            ),
            "object_reference_writer_facts": len(
                object_reference_writers
            ),
            "object_reference_reader_facts": len(
                object_reference_readers
            ),
            "object_reference_shared_objects": len(
                list(
                    object_reference_shared_result.get(
                        "shared_objects", []
                    )
                    or []
                )
            ),
            "deferred_callback_channel_edges": len(deferred_channel_edges),
            "source_centric_channel_edges": len(
                source_centric_channel_edges
            ),
            "source_associations": len(source_associations),
            "admitted_source_centric_shared_objects": len(
                list(shared_object_result.get("shared_objects", []) or [])
            ),
            "admitted_source_associated_transport_objects": len(
                list(
                    source_associated_transport_result.get(
                        "shared_objects", []
                    )
                    or []
                )
            ),
            "memory_access_write_facts": len(
                access_fact_index.write_facts
            ),
            "memory_access_read_facts": len(
                access_fact_index.read_facts
            ),
            "memory_access_fact_blockers": len(
                access_fact_index.blockers
            ),
            "optional_callback_targets_applied": (
                optional_callback_targets_applied
            ),
            "bounded_container_aliases": len(bounded_container_aliases),
            "primitive_shared_objects": len(primitive_shared_object_ids),
            "channel_write_edges": len(
                [edge for edge in channel_edges if edge.get("edge_kind") == "CHANNEL_WRITE"]
            ),
            "channel_read_edges": len(
                [edge for edge in channel_edges if edge.get("edge_kind") == "CHANNEL_READ"]
            ),
            "candidate_channel_edges": len(candidate_channel_edges),
            "exact_channel_edges": len(exact_channel_edges),
            "legacy_channel_edges": len(legacy_channel_edges),
            "source_overlay_edges": len(source_overlay_edges),
            "deterministic_source_write_candidates": len(source_write_candidates),
            "channel_blockers": len(channel_blockers),
            "value_object_bindings": len(value_object_bindings),
            "object_write_edges": len(
                [
                    edge
                    for edge in candidate_channel_edges
                    if edge.get("edge_kind") == "OBJECT_WRITE"
                ]
            ),
            "object_read_edges": len(
                [
                    edge
                    for edge in candidate_channel_edges
                    if edge.get("edge_kind") == "OBJECT_READ"
                ]
            ),
            "legacy_seed_objects": len(list(legacy.get("object_nodes", []) or [])),
        },
        "legacy_seed_metadata": {
            "schema_version": legacy.get("schema_version"),
            "params": legacy.get("params", {}),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2) + "\n")
    print(json.dumps(artifact["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
