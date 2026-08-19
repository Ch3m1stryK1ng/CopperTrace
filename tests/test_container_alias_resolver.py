import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "container_alias_resolver", ROOT / "scripts" / "container_alias_resolver.py"
)
resolver = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = resolver
SPEC.loader.exec_module(resolver)


def node(value_id, *, object_id="", slot=None, constant=False, size=4):
    return {
        "value_id": value_id,
        "object_id": object_id or value_id.replace("value:", "object:"),
        "parameter_slot": slot,
        "is_parameter": slot is not None,
        "is_input": slot is not None,
        "is_constant": constant,
        "size": size,
    }


def op(site, mnemonic, output, *inputs):
    return {
        "site_id": site,
        "mnemonic": mnemonic,
        "output": output,
        "inputs": list(inputs),
    }


def test_recovers_formal_rooted_loop_carried_container_alias_without_names():
    formal = node("value:formal", object_id="param:00001000:0", slot=0)
    initial_address = node("value:initial-address")
    initial_member = node("value:initial-member")
    recurrence_address = node("value:recurrence-address")
    recurrence_member = node("value:recurrence-member")
    loop_member = node("value:loop-member")
    facts = {
        "functions": [
            {
                "function_id": "fn:00001000",
                "name": "renamed_container_consumer",
                "parameters": [{"index": 0, "object_id": "param:00001000:0"}],
                "pcode_ops": [
                    op("site:init-address", "PTRSUB", initial_address, formal, node("const:field", constant=True)),
                    op("site:init-load", "LOAD", initial_member, node("const:space", constant=True), initial_address),
                    op("site:phi", "MULTIEQUAL", loop_member, initial_member, recurrence_member),
                    op("site:next-address", "PTRSUB", recurrence_address, loop_member, node("const:next", constant=True)),
                    op("site:next-load", "LOAD", recurrence_member, node("const:space2", constant=True), recurrence_address),
                ],
            }
        ]
    }

    aliases = resolver.build_bounded_container_aliases(facts)

    assert len(aliases) == 1
    alias = aliases[0]
    assert alias["loop_atom_id"] == "value:loop-member"
    assert alias["root_parameter_slot"] == 0
    assert alias["root_atom_id"] == "value:formal"
    assert alias["initial_load_sites"] == ["site:init-load"]
    assert alias["recurrence_load_sites"] == ["site:next-load"]
    assert alias["analysis_precision"] == "MAY"
    assert alias["max_container_hops"] == 1


def test_does_not_promote_phi_without_formal_rooted_initial_load():
    left = node("value:left")
    right = node("value:right")
    facts = {
        "functions": [
            {
                "function_id": "fn:00002000",
                "name": "renamed_internal_loop",
                "parameters": [],
                "pcode_ops": [op("site:phi", "MULTIEQUAL", node("value:phi"), left, right)],
            }
        ]
    }

    assert resolver.build_bounded_container_aliases(facts) == []


def test_does_not_promote_unrelated_recurrence_load():
    formal = node("value:formal", object_id="param:00003000:0", slot=0)
    initial_address = node("value:initial-address")
    initial_member = node("value:initial-member")
    unrelated_address = node("value:unrelated-address")
    recurrence_member = node("value:recurrence-member")
    loop_member = node("value:loop-member")
    facts = {
        "functions": [
            {
                "function_id": "fn:00003000",
                "name": "renamed_container_consumer",
                "parameters": [{"index": 0, "object_id": "param:00003000:0"}],
                "pcode_ops": [
                    op("site:init-address", "PTRSUB", initial_address, formal, node("const:field", constant=True)),
                    op("site:init-load", "LOAD", initial_member, node("const:space", constant=True), initial_address),
                    op("site:next-load", "LOAD", recurrence_member, node("const:space2", constant=True), unrelated_address),
                    op("site:phi", "MULTIEQUAL", loop_member, initial_member, recurrence_member),
                ],
            }
        ]
    }

    assert resolver.build_bounded_container_aliases(facts) == []
