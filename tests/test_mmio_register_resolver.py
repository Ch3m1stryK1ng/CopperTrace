from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from mmio_register_resolver import MMIORegisterResolver  # noqa: E402


def profile(registers: list[dict], **extra: object) -> dict:
    return {
        "schema_version": "ct-mini-hardware-metadata-v2",
        "metadata_source": "typed_register_map",
        "platform_id": "test-platform",
        "registers": registers,
        **extra,
    }


def register(role: str, **match: object) -> dict:
    return {
        **match,
        "role": role,
        "evidence_source": "svd",
        "evidence_reference": "device.svd",
    }


class MMIORegisterResolverTests(unittest.TestCase):
    def test_resolves_rx_by_absolute_address(self) -> None:
        resolver = MMIORegisterResolver(
            profile([register("RX_DATA", address="0x40001004", register="RDR")])
        )

        result = resolver.resolve(0x40001004)

        self.assertTrue(result["resolved"])
        self.assertEqual(result["role"], "RX_DATA")
        self.assertEqual(result["match_kind"], "absolute_address")

    def test_resolves_status_by_typed_base_and_offset(self) -> None:
        resolver = MMIORegisterResolver(
            profile(
                [
                    register(
                        "STATUS",
                        peripheral_type="UART_Type",
                        field_offset="0x0",
                        register="SR",
                    )
                ]
            )
        )

        result = resolver.resolve(
            peripheral_type="UART_Type", typed_base="0x40001000", constant_offset=0
        )

        self.assertTrue(result["resolved"])
        self.assertEqual(result["role"], "STATUS")
        self.assertEqual(result["match_kind"], "typed_base_offset")
        self.assertEqual(result["address"], "0x40001000")

    def test_resolves_tx_by_instance_base_and_offset(self) -> None:
        resolver = MMIORegisterResolver(
            profile(
                [
                    register(
                        "TX_DATA",
                        peripheral_type="UART_Type",
                        field_offset="0x8",
                        register="TDR",
                    )
                ],
                peripheral_instances=[
                    {
                        "peripheral_instance": "UART0",
                        "peripheral_type": "UART_Type",
                        "instance_base": "0x40001000",
                    }
                ],
            )
        )

        result = resolver.resolve(instance_base="0x40001000", offset="0x8")

        self.assertTrue(result["resolved"])
        self.assertEqual(result["role"], "TX_DATA")
        self.assertEqual(result["match_kind"], "instance_base_offset")

    def test_explicit_unknown_is_a_resolved_profile_entry(self) -> None:
        resolver = MMIORegisterResolver(
            profile([register("UNKNOWN", address="0x4000100c")])
        )

        result = resolver.resolve(0x4000100C)

        self.assertTrue(result["resolved"])
        self.assertEqual(result["role"], "UNKNOWN")

    def test_conflicting_roles_are_unresolved(self) -> None:
        resolver = MMIORegisterResolver(
            profile(
                [
                    register("RX_DATA", address="0x40001004"),
                    register("TX_DATA", address="0x40001004"),
                ]
            )
        )

        result = resolver.resolve(0x40001004)

        self.assertFalse(result["resolved"])
        self.assertEqual(result["role"], "UNKNOWN")
        self.assertEqual(result["reason"], "conflicting_register_roles")

    def test_v1_register_metadata_roles_are_compatible(self) -> None:
        resolver = MMIORegisterResolver(
            {
                "schema_version": "ct-mini-hardware-metadata-v1",
                "metadata_source": "svd",
                "binary_sha256": "0" * 64,
                "register_metadata": [
                    {"address": "0x40002000", "role": "DATA"},
                    {"address": "0x40002004", "role": "STATUS"},
                    {"address": "0x40002008", "role": "CONTROL"},
                ],
                "dma_functions": {},
            }
        )

        expected = {
            0x40002000: "EXTERNAL_INPUT_DATA",
            0x40002004: "STATUS",
            0x40002008: "CONTROL",
        }
        for address, role in expected.items():
            with self.subTest(address=hex(address)):
                result = resolver.resolve(address)
                self.assertTrue(result["resolved"])
                self.assertEqual(result["role"], role)


if __name__ == "__main__":
    unittest.main()
