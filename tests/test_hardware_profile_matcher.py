import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from hardware_profile_matcher import select_hardware_profile  # noqa: E402
from mmio_register_resolver import MMIORegisterResolver  # noqa: E402


def profile(profile_id, registers, *, required_symbol=""):
    row = {
        "schema_version": "ct-mini-hardware-metadata-v2",
        "scope": "platform",
        "metadata_source": "svd",
        "platform_id": profile_id,
        "registers": registers,
    }
    if required_symbol:
        row["binary_identity"] = {"required_symbols": [required_symbol]}
    return row


def register(address, role, *, base="0x40001000", access=""):
    row = {
        "address": address,
        "instance_base": base,
        "field_offset": hex(int(address, 0) - int(base, 0)),
        "peripheral_instance": "PERIPH0",
        "role": role,
        "evidence_source": "svd",
        "evidence_reference": "fixture",
    }
    if access:
        row["access"] = access
    return row


def accesses(*rows):
    return [
        {"address": address, "access": access, "site_id": f"site:{index}"}
        for index, (address, access) in enumerate(rows)
    ]


def test_exact_elf_identity_enables_profile_without_absolute_register_cluster():
    candidate = profile(
        "soc-a",
        [
            register("0x40001000", "STATUS"),
            register("0x40001004", "RX_DATA"),
        ],
        required_symbol="CONFIG_SOC_A",
    )
    result = select_hardware_profile(
        [candidate],
        elf_symbols={"CONFIG_SOC_A": [1]},
        observed_accesses=accesses(("0x40001004", "READ")),
    )
    assert result["status"] == "resolved"
    assert result["mode"] == "elf_identity"
    assert result["selected_profile_ids"] == ["soc-a"]


def test_unmatched_identity_still_requires_register_cluster():
    candidate = profile(
        "soc-a",
        [
            register("0x40001000", "STATUS"),
            register("0x40001004", "RX_DATA"),
        ],
        required_symbol="CONFIG_SOC_A",
    )
    result = select_hardware_profile(
        [candidate],
        elf_symbols={},
        observed_accesses=accesses(("0x40001004", "READ")),
    )
    assert result["status"] == "unresolved"
    assert result["reason"] == "no_elf_identity_or_register_cluster_match"


def test_identity_and_two_register_cluster_select_profile():
    candidate = profile(
        "soc-a",
        [
            register("0x40001000", "STATUS"),
            register("0x40001004", "RX_DATA"),
        ],
        required_symbol="CONFIG_SOC_A",
    )
    result = select_hardware_profile(
        [candidate],
        elf_symbols={"CONFIG_SOC_A": [1]},
        observed_accesses=accesses(
            ("0x40001000", "READ"),
            ("0x40001004", "READ"),
        ),
    )
    assert result["status"] == "resolved"
    assert result["mode"] == "elf_identity_plus_register_cluster"
    assert result["selected_profile_ids"] == ["soc-a"]


def test_register_first_selects_unique_cluster_without_identity():
    candidate = profile(
        "soc-a",
        [
            register("0x40001000", "STATUS"),
            register("0x40001004", "RX_DATA"),
        ],
    )
    unrelated = profile(
        "soc-b",
        [
            register("0x50002000", "STATUS", base="0x50002000"),
            register("0x50002004", "RX_DATA", base="0x50002000"),
        ],
    )
    result = select_hardware_profile(
        [candidate, unrelated],
        elf_symbols={},
        observed_accesses=accesses(
            ("0x40001000", "READ"),
            ("0x40001004", "READ"),
        ),
    )
    assert result["status"] == "resolved"
    assert result["mode"] == "register_cluster_only"
    assert result["selected_profile_ids"] == ["soc-a"]


def test_conflicting_profiles_do_not_produce_consensus_role():
    first = profile(
        "soc-a",
        [
            register("0x40001000", "STATUS"),
            register("0x40001004", "RX_DATA"),
        ],
    )
    second = profile(
        "soc-b",
        [
            register("0x40001000", "STATUS"),
            register("0x40001004", "STATUS"),
        ],
    )
    result = select_hardware_profile(
        [first, second],
        elf_symbols={},
        observed_accesses=accesses(
            ("0x40001000", "READ"),
            ("0x40001004", "READ"),
        ),
    )
    assert result["status"] == "resolved"
    assert result["selected_profile_ids"] == ["soc-a", "soc-b"]
    resolver = MMIORegisterResolver(result["profile"])
    assert resolver.resolve("0x40001004")["resolved"] is False


def test_dma_register_roles_are_resolved_by_existing_resolver():
    candidate = profile(
        "soc-dma",
        [
            register("0x40001000", "DMA_RX_BUFFER_POINTER", access="write-only"),
            register("0x40001004", "DMA_START", access="write-only"),
        ],
    )
    resolver = MMIORegisterResolver(candidate)
    assert resolver.resolve("0x40001000")["role"] == "DMA_RX_BUFFER_POINTER"
    assert resolver.resolve("0x40001004")["role"] == "DMA_START"


def test_all_hardware_profiles_validate_against_registry_schema():
    schema = json.loads(
        (ROOT / "schemas/hardware_metadata.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    profiles = sorted((ROOT / "registries/hardware").glob("*.profile.json"))
    assert profiles
    for path in profiles:
        validator.validate(json.loads(path.read_text(encoding="utf-8")))
