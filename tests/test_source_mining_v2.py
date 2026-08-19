from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_source_artifacts as miner  # noqa: E402
import device_dispatch_resolver  # noqa: E402


REGISTRY = json.loads((ROOT / "registries" / "source_patterns.v0.json").read_text())


@unittest.skipUnless(shutil.which("gcc"), "gcc is required for ELF identity fixture")
class HardwareProfileIdentityTests(unittest.TestCase):
    def test_required_absolute_soc_symbol_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "identity.c"
            binary = root / "identity.elf"
            source.write_text(
                'asm(".globl CONFIG_SOC_PART_NUMBER_TEST\\n"'
                '    ".set CONFIG_SOC_PART_NUMBER_TEST, 1\\n");\n'
                "int main(void) { return 0; }\n"
            )
            subprocess.run(
                ["gcc", str(source), "-o", str(binary)], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            result = miner.verified_elf_identity(binary, {
                "required_symbols": [{
                    "name": "CONFIG_SOC_PART_NUMBER_TEST", "value": "0x1",
                }],
            })
            self.assertEqual(result["status"], "verified")
            self.assertEqual(
                result["matched_symbols"][0]["name"],
                "CONFIG_SOC_PART_NUMBER_TEST",
            )

    def test_profile_for_a_different_soc_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "identity.c"
            binary = root / "identity.elf"
            source.write_text("int main(void) { return 0; }\n")
            subprocess.run(
                ["gcc", str(source), "-o", str(binary)], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            with self.assertRaises(SystemExit):
                miner.verified_elf_identity(binary, {
                    "required_symbols": ["CONFIG_SOC_PART_NUMBER_OTHER"],
                })


def varnode(
    object_id: str,
    *,
    offset: str = "0x0",
    constant: bool = False,
    name: str = "",
    parameter: bool = False,
    slot: int | None = None,
    value_id: str = "",
    address: bool = False,
    high_type: str = "",
) -> dict:
    return {
        "object_id": object_id,
        "value_id": value_id or object_id,
        "offset": offset,
        "is_constant": constant,
        "high_name": name,
        "high_data_type": high_type,
        "is_parameter": parameter,
        "parameter_slot": slot,
        "is_address": address,
    }


def sam3x_profile(role: str, offset: str) -> dict:
    return {
        "schema_version": "ct-mini-hardware-metadata-v2",
        "scope": "platform",
        "metadata_source": "trusted_platform_summary",
        "platform_id": "test-sam3x",
        "mmio_ranges": [{
            "start": "0x40000000", "end": "0x5fffffff",
            "evidence_source": "test", "evidence_reference": "test manual",
        }],
        "registers": [{
            "peripheral_type": "Spi", "field_offset": offset,
            "register": {"0x8": "SPI_RDR", "0xc": "SPI_TDR", "0x10": "SPI_SR"}[offset],
            "role": role, "evidence_source": "vendor_manual",
            "evidence_reference": "SAM3X SPI register map",
        }],
    }


def typed_mmio_facts(*, offset: str, with_store: bool = True) -> dict:
    regs = varnode(
        "param:00001000:0", name="regs", parameter=True, slot=0,
        value_id="value:regs", high_type="Spi *",
    )
    pointer = varnode("unique:mmio-pointer", value_id="value:mmio-pointer")
    value = varnode("unique:mmio-value", value_id="value:mmio-value", name="rx_value")
    destination = varnode(
        "param:00001000:1", name="dst", parameter=True, slot=1,
        value_id="value:dst", high_type="uint8_t *",
    )
    operations = [
        {
            "site_id": "site:00001000:00001008:1", "mnemonic": "PTRSUB",
            "output": pointer,
            "inputs": [regs, varnode("const:field", offset=offset, constant=True)],
        },
        {
            "site_id": "site:00001000:0000100c:1", "mnemonic": "LOAD",
            "output": value,
            "inputs": [varnode("const:space", offset="0x1", constant=True), pointer],
        },
    ]
    if with_store:
        operations.append({
            "site_id": "site:00001000:00001010:1", "mnemonic": "STORE",
            "output": None,
            "inputs": [
                varnode("const:space2", offset="0x1", constant=True), destination, value,
            ],
        })
    else:
        condition = varnode("unique:condition", value_id="value:condition")
        operations.extend([
            {
                "site_id": "site:00001000:00001010:1", "mnemonic": "INT_AND",
                "output": condition,
                "inputs": [value, varnode("const:mask", offset="0xff", constant=True)],
            },
            {
                "site_id": "site:00001000:00001014:1", "mnemonic": "CBRANCH",
                "output": None,
                "inputs": [varnode("const:target", offset="0x1020", constant=True), condition],
            },
        ])
    return {
        "hardware_profile": {},
        "functions": [{
            "name": "generic_driver", "function_id": "fn:00001000",
            "parameters": [
                {"index": 0, "name": "regs", "data_type": "Spi *"},
                {"index": 1, "name": "dst", "data_type": "uint8_t *"},
            ],
            "decompiled_c": "void generic_driver(Spi *regs, uint8_t *dst) { *dst = regs->field; }",
            "pcode_ops": operations,
        }],
    }


def mmio_facts(code: str, *, mmio_address: str = "0x40010000") -> dict:
    value = varnode("ssa:1000:value", name="rx_value")
    destination = varnode("param:00001000:1", name="dst", parameter=True, slot=1)
    return {
        "functions": [
            {
                "name": "driver_receive",
                "function_id": "fn:00001000",
                "entry": "0x1000",
                "decompiled_c": code,
                "pcode_ops": [
                    {
                        "site_id": "site:00001000:00001010:1",
                        "mnemonic": "LOAD",
                        "output": value,
                        "inputs": [
                            varnode("const:space", offset="0x1", constant=True),
                            varnode("const:mmio", offset=mmio_address, constant=True),
                        ],
                    },
                    {
                        "site_id": "site:00001000:00001014:2",
                        "mnemonic": "STORE",
                        "output": None,
                        "inputs": [
                            varnode("const:space", offset="0x1", constant=True),
                            destination,
                            value,
                        ],
                    },
                ],
            }
        ]
    }


class StructuredSourceMiningTests(unittest.TestCase):
    def test_fact_export_selection_adds_named_source_target_without_confirming_it(self) -> None:
        functions = [
            miner.FunctionRecord(
                name="selected_rx_context",
                signature="void selected_rx_context(void)",
                params=[],
                start_line=1,
                body_start_line=2,
                end_line=5,
                lines=[
                    "void selected_rx_context(void)\n",
                    "{\n",
                    "  neutral_internal_helper(packet);\n",
                    "  symbol_only_read(packet);\n",
                    "}\n",
                ],
            ),
            miner.FunctionRecord(
                name="neutral_internal_helper",
                signature="void neutral_internal_helper(void *out)",
                params=["void *out"],
                start_line=6,
                body_start_line=7,
                end_line=9,
                lines=[
                    "void neutral_internal_helper(void *out)\n",
                    "{\n",
                    "  *(unsigned char *)out = *(volatile unsigned char *)0x40001000;\n",
                    "}\n",
                ],
            ),
        ]

        selected = miner.expand_selected_source_callees(
            functions, ["selected_rx_context"], REGISTRY
        )

        self.assertEqual(
            selected,
            [
                "selected_rx_context",
                "symbol_only_read",
            ],
        )

    def test_profile_rx_data_plus_typed_offset_confirms_mmio_source(self) -> None:
        facts = typed_mmio_facts(offset="0x8")
        facts["hardware_profile"] = sam3x_profile("RX_DATA", "0x8")
        confirmed, candidates, raw, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(candidates, [])
        self.assertEqual(raw, [])
        self.assertEqual(confirmed[0]["source_buffer"], "dst")
        resolution = confirmed[0]["proof"]["register_resolution"]
        self.assertEqual(resolution["match_kind"], "typed_base_offset")
        self.assertEqual(resolution["register"], "SPI_RDR")
        self.assertEqual(resolution["role"], "RX_DATA")

    def test_typed_ram_field_without_hardware_evidence_is_not_mmio(self) -> None:
        facts = typed_mmio_facts(offset="0x8")

        confirmed, candidates, raw, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )

        self.assertEqual(confirmed, [])
        self.assertEqual(candidates, [])
        self.assertEqual(raw, [])

    def test_duplex_transfer_receive_candidate_is_name_independent(self) -> None:
        instance = varnode(
            "param:00001000:0", name="transport", parameter=True, slot=0,
            value_id="value:transport", high_type="void *",
        )
        receive_buffer = varnode(
            "param:00001000:1", name="output", parameter=True, slot=1,
            value_id="value:output", high_type="uint8_t *",
        )
        receive_length = varnode(
            "param:00001000:2", name="available", parameter=True, slot=2,
            value_id="value:available", high_type="size_t",
        )
        facts = {
            "functions": [
                {
                    "name": "transport_worker",
                    "function_id": "fn:00001000",
                    "entry": "0x1000",
                    "parameters": [
                        {"index": 0, "name": "transport", "data_type": "void *"},
                        {"index": 1, "name": "output", "data_type": "uint8_t *"},
                        {"index": 2, "name": "available", "data_type": "size_t"},
                    ],
                    "decompiled_c": "void transport_worker(void *transport, uint8_t *output, size_t available) { exchange(transport, 0, 0, output, available); }",
                    "pcode_ops": [{
                        "site_id": "site:00001000:00001020:1",
                        "mnemonic": "CALL",
                        "output": None,
                        "inputs": [
                            varnode("const:target", offset="0x2000", constant=True),
                            instance,
                            varnode("const:null", offset="0x0", constant=True),
                            varnode("const:zero", offset="0x0", constant=True),
                            receive_buffer,
                            receive_length,
                            varnode(
                                "param:00001000:3", name="done", parameter=True,
                                slot=3, value_id="value:done",
                                high_type="void (*)(void)",
                            ),
                        ],
                        "call": {
                            "kind": "CALL",
                            "target_function": "exchange",
                            "target_function_id": "fn:00002000",
                        },
                    }],
                },
                {
                    "name": "exchange",
                    "function_id": "fn:00002000",
                    "entry": "0x2000",
                    "parameters": [
                        {"index": 0, "name": "state", "data_type": "void *"},
                        {"index": 1, "name": "out_data", "data_type": "const uint8_t *"},
                        {"index": 2, "name": "out_size", "data_type": "size_t"},
                        {"index": 3, "name": "in_data", "data_type": "uint8_t *"},
                        {"index": 4, "name": "in_size", "data_type": "size_t"},
                        {"index": 5, "name": "done", "data_type": "void (*)(void)"},
                    ],
                    "decompiled_c": "int exchange(void *state, const uint8_t *out_data, size_t out_size, uint8_t *in_data, size_t in_size);",
                    "pcode_ops": [],
                },
            ],
        }

        candidates, next_index = miner.scan_duplex_transfer_receive_candidates(
            facts, start_candidate_index=1
        )

        self.assertEqual(next_index, 2)
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["function"], "transport_worker")
        self.assertEqual(candidate["candidate_source_buffer"], "output")
        self.assertEqual(
            candidate["static_bindings"]["source_actual_arg_index"], 3
        )
        row = miner.heuristic_source_row(candidate, "SO0001")
        self.assertIsNotNone(row)
        self.assertEqual(row["rule_id"], "SOURCE_DUPLEX_TRANSFER_RECEIVE_OUTPUT")
        self.assertEqual(row["decision"], "ACCEPT_HEURISTIC")

    def test_callback_output_copy_candidate_requires_object_evidence(self) -> None:
        callback_entry = 0x3000
        table_address = 0x20000000
        frame_address = 0x20000100
        image = bytearray(0x200)
        image[0:4] = (callback_entry | 1).to_bytes(4, "little")
        memory = device_dispatch_resolver.InitializedMemory(
            [
                device_dispatch_resolver.MemoryRegion(
                    start=table_address,
                    data=bytes(image),
                    source="elf:PT_LOAD[0]",
                    writable=True,
                    name=".data",
                )
            ],
            symbols=[
                device_dispatch_resolver.MemorySymbol(
                    address=table_address,
                    size=4,
                    kind="STT_OBJECT",
                    name="driver_table",
                    section=".data",
                    writable=True,
                ),
                device_dispatch_resolver.MemorySymbol(
                    address=frame_address,
                    size=64,
                    kind="STT_OBJECT",
                    name="pending_frame",
                    section=".bss",
                    writable=True,
                ),
            ],
        )
        output = varnode(
            "param:00003000:0", name="output", parameter=True, slot=0,
            value_id="value:output", high_type="uint8_t *",
        )
        extent = varnode(
            "param:00003000:1", name="frame_size", parameter=True, slot=1,
            value_id="value:frame-size", high_type="size_t",
        )
        facts = {
            "functions": [
                {
                    "name": "driver_operation",
                    "function_id": "fn:00003000",
                    "entry": "0x3000",
                    "parameters": [
                        {"index": 0, "name": "output", "data_type": "uint8_t *"},
                        {"index": 1, "name": "frame_size", "data_type": "size_t"},
                    ],
                    "decompiled_c": "size_t driver_operation(uint8_t *output, size_t frame_size) { memcpy(output, pending_frame, frame_size); return frame_size; }",
                    "pcode_ops": [
                        {
                            "site_id": "site:00003000:00003010:1",
                            "mnemonic": "CALL",
                            "output": None,
                            "inputs": [
                                varnode("const:memcpy", offset="0x4000", constant=True),
                                output,
                                varnode(
                                    "const:frame",
                                    offset=hex(frame_address),
                                    constant=True,
                                    address=True,
                                ),
                                extent,
                            ],
                            "call": {
                                "kind": "CALL",
                                "target_function": "memcpy",
                                "target_function_id": "fn:00004000",
                            },
                        },
                        {
                            "site_id": "site:00003000:00003018:2",
                            "mnemonic": "RETURN",
                            "output": None,
                            "inputs": [
                                varnode("const:return-space", offset="0x0", constant=True),
                                extent,
                            ],
                        },
                    ],
                },
                {
                    "name": "memcpy",
                    "function_id": "fn:00004000",
                    "entry": "0x4000",
                    "parameters": [],
                    "decompiled_c": "",
                    "pcode_ops": [],
                },
            ],
        }

        candidates, next_index = miner.scan_callback_output_copy_candidates(
            facts, memory, start_candidate_index=1
        )

        self.assertEqual(next_index, 2)
        self.assertEqual(len(candidates), 1)
        candidate = candidates[0]
        self.assertEqual(candidate["candidate_source_buffer"], "output")
        self.assertEqual(
            candidate["static_bindings"]["copy_source_address"],
            hex(frame_address),
        )
        row = miner.heuristic_source_row(candidate, "SO0001")
        self.assertIsNotNone(row)
        self.assertEqual(row["rule_id"], "SOURCE_CALLBACK_TABLE_OUTPUT_COPY")
        self.assertEqual(row["decision"], "ACCEPT_HEURISTIC")

    def test_profile_status_and_tx_roles_do_not_become_sources(self) -> None:
        for role, offset in (("STATUS", "0x10"), ("TX_DATA", "0xc")):
            with self.subTest(role=role):
                facts = typed_mmio_facts(offset=offset)
                facts["hardware_profile"] = sam3x_profile(role, offset)
                confirmed, candidates, raw, _, _ = miner.structured_mmio_and_dma_scan(
                    facts, REGISTRY, start_source_index=1, start_candidate_index=1
                )
                self.assertEqual(confirmed, [])
                self.assertEqual(candidates, [])
                self.assertEqual(len(raw), 1)
                self.assertEqual(raw[0]["register_role"], role)

    def test_profile_rx_data_can_bind_source_value_without_buffer(self) -> None:
        facts = typed_mmio_facts(offset="0x8", with_store=False)
        facts["hardware_profile"] = sam3x_profile("RX_DATA", "0x8")
        confirmed, candidates, raw, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(candidates, [])
        self.assertEqual(raw, [])
        self.assertEqual(confirmed[0]["source_buffer"], "")
        self.assertEqual(confirmed[0]["source_output_kind"], "scalar_value")
        self.assertEqual(confirmed[0]["source_value_id"], "value:mmio-value")

    def test_core_miner_has_no_dataset_source_name_shortcuts(self) -> None:
        implementation = (ROOT / "scripts" / "build_source_artifacts.py").read_text()
        registry_text = (ROOT / "registries" / "source_patterns.v0.json").read_text()
        forbidden = {
            "packetbuf_dataptr",
            "packetbuf_datalen",
            "uip_newdata",
            "ieee802154_recv",
            "USBH_ParseCfgDesc",
            "input_l2cap_credit",
            "bt_spi_transceive",
            "spi_sam_fast_rx",
        }
        for name in forbidden:
            with self.subTest(name=name):
                self.assertNotIn(name, implementation)
                self.assertNotIn(name, registry_text)

    def test_named_data_register_without_metadata_is_heuristic(self) -> None:
        facts = mmio_facts("void driver_receive(Regs *regs, char *dst) { *dst = regs->RDR; }")
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )

        self.assertEqual(confirmed, [])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["candidate_source_buffer"], "dst")

        facts["register_metadata"] = [{"address": "0x40010000", "role": "DATA"}]
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(candidates, [])
        self.assertEqual(confirmed[0]["source_object_id"], "param:00001000:1")

    def test_source_buffer_binds_through_formal_field_pointer_load(self) -> None:
        rx_param = varnode("param:00001000:1", name="rx_buf", parameter=True, slot=1)
        field_address = varnode("unique:field-address", name="rx_buf_field", value_id="value:field-address")
        destination = varnode("reg:1000:30:4", name="puVar3", value_id="value:destination")
        mmio_value = varnode("reg:1000:34:1", name="value", value_id="value:mmio")
        facts = {"functions": [{
            "name": "driver_receive", "function_id": "fn:00001000",
            "decompiled_c": "void driver_receive(Regs *regs, Buf *rx_buf) { puVar3 = rx_buf->buf; *puVar3 = regs->RDR; }",
            "pcode_ops": [
                {
                    "site_id": "site:00001000:00001004:1", "mnemonic": "PTRSUB", "output": field_address,
                    "inputs": [rx_param, varnode("const:field", offset="0x4", constant=True)],
                },
                {
                    "site_id": "site:00001000:00001008:1", "mnemonic": "LOAD", "output": destination,
                    "inputs": [varnode("const:space", offset="1", constant=True), field_address],
                },
                {
                    "site_id": "site:00001000:0000100c:1", "mnemonic": "LOAD", "output": mmio_value,
                    "inputs": [varnode("const:space2", offset="1", constant=True),
                               varnode("const:mmio", offset="0x40010000", constant=True)],
                },
                {
                    "site_id": "site:00001000:00001010:1", "mnemonic": "STORE", "output": None,
                    "inputs": [varnode("const:space3", offset="1", constant=True), destination, mmio_value],
                },
            ],
        }]}
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(candidates[0]["candidate_source_buffer"], "rx_buf")
        self.assertEqual(candidates[0]["candidate_source_object_id"], "param:00001000:1")

    def test_exact_formal_access_overrides_conflicting_name_hint(self) -> None:
        function = {
            "function_id": "fn:00001000",
            "parameters": [
                {"index": 2, "name": "tx_bufs", "object_id": "param:00001000:2"},
                {"index": 3, "name": "rx_bufs", "object_id": "param:00001000:3"},
            ],
        }
        misleading = {
            "parameter_slot": 2,
            "high_name": "tx_bufs",
            "object_id": "param:00001000:2",
        }
        resolved = miner.canonical_formal_parameter(
            function, misleading, (3, (0, 0))
        )
        self.assertEqual(resolved["parameter_slot"], 3)
        self.assertEqual(resolved["high_name"], "rx_bufs")
        self.assertEqual(resolved["object_id"], "param:00001000:3")

    def test_isr_label_requires_vector_entry_not_handler_name(self) -> None:
        facts = mmio_facts("void UART_IRQHandler(Regs *regs, char *dst) { *dst = regs->RDR; }")
        facts["functions"][0]["name"] = "UART_IRQHandler"
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(candidates[0]["label_hint"], "MMIO_READ")

        facts["functions"][0]["is_interrupt_entry"] = True
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(candidates[0]["label_hint"], "ISR_MMIO_READ")

    def test_unknown_mmio_to_buffer_requires_confirmation(self) -> None:
        facts = mmio_facts("void driver_receive(char *dst) { *dst = _DAT_40010000; }")
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )

        self.assertEqual(confirmed, [])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["candidate_kind"], "unknown_mmio_to_buffer_candidate")
        self.assertEqual(candidates[0]["candidate_source_object_id"], "param:00001000:1")
        semantic_slice = candidates[0]["semantic_slice"]
        self.assertIn("*dst = _DAT_40010000", semantic_slice["anchor"]["c_statement"])
        self.assertEqual(
            semantic_slice["anchor"]["destination"]["object_id"],
            "param:00001000:1",
        )
        self.assertIn("ram_store", semantic_slice["anchor_use"]["use_classes"])
        self.assertEqual(
            [row["mnemonic"] for row in semantic_slice["anchor_use"]["forward_slice"]],
            ["STORE"],
        )

        enriched = miner.enrich_candidates_with_program_facts(candidates, facts)
        self.assertEqual(
            enriched[0]["static_bindings"]["site_binding_status"],
            "verified_high_pcode_def_use_site",
        )

    def test_unknown_mmio_slice_summarizes_peer_branch_use(self) -> None:
        facts = mmio_facts("void driver_receive(char *dst) { *dst = _DAT_40010000; }")
        function = facts["functions"][0]
        status = varnode("ssa:1000:status", name="status")
        condition = varnode("ssa:1000:condition", name="condition")
        function["pcode_ops"].extend([
            {
                "site_id": "site:00001000:00001018:3", "mnemonic": "LOAD", "output": status,
                "inputs": [varnode("const:s", offset="1", constant=True),
                           varnode("const:m", offset="0x40010004", constant=True)],
            },
            {
                "site_id": "site:00001000:0000101a:4", "mnemonic": "INT_AND", "output": condition,
                "inputs": [status, varnode("const:mask", offset="1", constant=True)],
            },
            {
                "site_id": "site:00001000:0000101c:5", "mnemonic": "CBRANCH", "output": None,
                "inputs": [varnode("const:target", offset="0x1020", constant=True), condition],
            },
        ])
        _, candidates, raw, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(len(candidates), 1)
        peer = candidates[0]["semantic_slice"]["peer_mmio_loads"][0]
        self.assertIn("branch", peer["use_classes"])
        self.assertEqual(peer["register_address"], "0x40010004")
        self.assertEqual(len(raw), 1)

    def test_relative_struct_offset_is_not_an_absolute_mmio_address(self) -> None:
        facts = mmio_facts(
            "void transceive(Regs *regs, char *rx, char *tx) { *rx = regs->RDR; }",
            mmio_address="0x8",
        )
        facts["functions"][0]["pcode_ops"][1]["inputs"][1] = varnode(
            "param:00001000:2", name="tx", parameter=True, slot=2
        )
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(candidates, [])

    def test_elf_literal_value_resolves_peripheral_pointer(self) -> None:
        literal = varnode("global:00202d9c:4", offset="0x202d9c", address=True)
        literal.update({
            "space": "ram",
            "initial_memory_value": "0x40088828",
            "initial_memory_source": "elf_initialized_nonwritable_segment",
        })
        self.assertEqual(
            miner.constant_from_varnode(literal, {}, allow_address_literal=True),
            0x40088828,
        )

    def test_exact_dispatch_formal_binding_resolves_nested_initialized_mmio_base(self) -> None:
        dev = varnode("param:00001000:0", name="dev", parameter=True, slot=0)
        config_field = varnode("unique:config-field", value_id="value:config-field")
        config = varnode("reg:config", value_id="value:config")
        base = varnode("reg:base", value_id="value:base")
        register_pointer = varnode("unique:register", value_id="value:register")
        function = {"pcode_ops": [
            {
                "site_id": "site:1000:1004:1", "mnemonic": "PTRSUB",
                "output": config_field,
                "inputs": [dev, varnode("const:4", offset="0x4", constant=True)],
            },
            {
                "site_id": "site:1000:1008:1", "mnemonic": "LOAD", "output": config,
                "inputs": [varnode("space:1", offset="1", constant=True), config_field],
            },
            {
                "site_id": "site:1000:100c:1", "mnemonic": "LOAD", "output": base,
                "inputs": [varnode("space:2", offset="1", constant=True), config],
            },
            {
                "site_id": "site:1000:1010:1", "mnemonic": "PTRSUB",
                "output": register_pointer,
                "inputs": [base, varnode("const:8", offset="0x8", constant=True)],
            },
        ]}
        _, definitions = miner.pcode_indexes(function)
        device = bytearray(8)
        device[4:8] = (0x5000).to_bytes(4, "little")
        config_bytes = (0x40008000).to_bytes(4, "little")
        memory = miner.device_dispatch_resolver.InitializedMemory.from_regions([
            miner.device_dispatch_resolver.MemoryRegion(0x8000, bytes(device)),
            miner.device_dispatch_resolver.MemoryRegion(0x5000, config_bytes),
        ])

        address = miner.constant_from_bound_varnode(
            register_pointer,
            definitions,
            parameter_constants={0: 0x8000},
            initialized_memory=memory,
        )

        self.assertEqual(address, 0x40008008)

    def test_named_data_register_does_not_contaminate_other_mmio_load(self) -> None:
        facts = mmio_facts(
            "void driver_receive(Regs *regs, char *dst1, char *dst2) { "
            "*dst1 = regs->RDR; *dst2 = _DAT_40010004; }"
        )
        function = facts["functions"][0]
        first_store = function["pcode_ops"][1]
        first_store["inputs"][1] = varnode(
            "param:00001000:1", name="dst1", parameter=True, slot=1
        )
        unknown_value = varnode("unique:1000:unknown", name="status_value")
        function["pcode_ops"].extend([
            {
                "site_id": "site:00001000:00001018:3",
                "mnemonic": "LOAD",
                "output": unknown_value,
                "inputs": [
                    varnode("const:space2", offset="0x1", constant=True),
                    varnode("const:mmio2", offset="0x40010004", constant=True),
                ],
            },
            {
                "site_id": "site:00001000:0000101c:4",
                "mnemonic": "STORE",
                "output": None,
                "inputs": [
                    varnode("const:space3", offset="0x1", constant=True),
                    varnode("param:00001000:2", name="dst2", parameter=True, slot=2),
                    unknown_value,
                ],
            },
        ])
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(
            [row["candidate_source_buffer"] for row in candidates],
            ["dst1", "dst2"],
        )
        self.assertEqual(candidates[0]["static_bindings"]["register_class_hint"], "DATA")
        self.assertEqual(candidates[1]["static_bindings"]["register_class_hint"], "UNKNOWN_MMIO")

    def test_named_data_register_does_not_contaminate_same_buffer_load(self) -> None:
        facts = mmio_facts(
            "void driver_receive(Regs *regs, char *dst) { "
            "*dst = regs->RDR; *dst = _DAT_40010004; }"
        )
        function = facts["functions"][0]
        unknown_value = varnode("unique:1000:unknown", name="status_value")
        function["pcode_ops"].extend([
            {
                "site_id": "site:00001000:00001018:3", "mnemonic": "LOAD", "output": unknown_value,
                "inputs": [varnode("const:s", offset="1", constant=True),
                           varnode("const:m", offset="0x40010004", constant=True)],
            },
            {
                "site_id": "site:00001000:0000101c:4", "mnemonic": "STORE", "output": None,
                "inputs": [varnode("const:s2", offset="1", constant=True),
                           varnode("param:00001000:1", name="dst", parameter=True, slot=1),
                           unknown_value],
            },
        ])
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(len(candidates), 2)

    def test_named_data_register_does_not_contaminate_same_unknown_pointee(self) -> None:
        value_a = varnode("reg:1000:10:1", name="data", value_id="value:data")
        value_b = varnode("reg:1000:14:1", name="status", value_id="value:status")
        dst_a = varnode("reg:1000:20:4", name="dst", value_id="value:dst-a")
        dst_b = varnode("reg:1000:20:4", name="dst", value_id="value:dst-b")
        facts = {"functions": [{
            "name": "driver_receive", "function_id": "fn:00001000",
            "decompiled_c": "void driver_receive(char *dst) { *dst = regs->RDR; *dst = _DAT_40010004; }",
            "pcode_ops": [
                {"site_id": "site:1000:1004:1", "mnemonic": "LOAD", "output": value_a,
                 "inputs": [varnode("const:s1", offset="1", constant=True), varnode("const:m1", offset="0x40010000", constant=True)]},
                {"site_id": "site:1000:1008:1", "mnemonic": "STORE", "output": None,
                 "inputs": [varnode("const:s2", offset="1", constant=True), dst_a, value_a]},
                {"site_id": "site:1000:100c:1", "mnemonic": "LOAD", "output": value_b,
                 "inputs": [varnode("const:s3", offset="1", constant=True), varnode("const:m2", offset="0x40010004", constant=True)]},
                {"site_id": "site:1000:1010:1", "mnemonic": "STORE", "output": None,
                 "inputs": [varnode("const:s4", offset="1", constant=True), dst_b, value_b]},
            ],
        }]}
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(len(candidates), 2)

    def test_value_id_keeps_multiple_ssa_definitions_distinct(self) -> None:
        function = {
            "pcode_ops": [
                {
                    "site_id": "site:1:1:1", "mnemonic": "COPY",
                    "output": varnode("reg:1:0:4", value_id="value:first"),
                    "inputs": [varnode("const:one", offset="0x1", constant=True)],
                },
                {
                    "site_id": "site:1:2:1", "mnemonic": "COPY",
                    "output": varnode("reg:1:0:4", value_id="value:second"),
                    "inputs": [varnode("const:two", offset="0x2", constant=True)],
                },
            ]
        }
        _, definitions = miner.pcode_indexes(function)
        self.assertEqual(miner.constant_from_varnode(varnode("reg:1:0:4", value_id="value:first"), definitions), 1)
        self.assertEqual(miner.constant_from_varnode(varnode("reg:1:0:4", value_id="value:second"), definitions), 2)

    def test_ptradd_uses_element_scale(self) -> None:
        function = {
            "pcode_ops": [{
                "site_id": "site:1:1:1", "mnemonic": "PTRADD",
                "output": varnode("unique:ptr", value_id="value:ptr"),
                "inputs": [
                    varnode("const:base", offset="0x20000000", constant=True),
                    varnode("const:index", offset="0x3", constant=True),
                    varnode("const:scale", offset="0x4", constant=True),
                ],
            }]
        }
        _, definitions = miner.pcode_indexes(function)
        self.assertEqual(
            miner.constant_from_varnode(varnode("unique:ptr", value_id="value:ptr"), definitions),
            0x2000000C,
        )

    def test_tied_memory_varnode_is_not_a_literal_value_by_default(self) -> None:
        node = varnode("global:0800014c:4", offset="0x0800014c", address=True)
        node["space"] = "ram"
        self.assertIsNone(miner.constant_from_varnode(node, {}))
        self.assertEqual(
            miner.constant_from_varnode(node, {}, allow_address_literal=True),
            0x0800014C,
        )

    def test_complex_receive_body_is_candidate_not_direct_confirmation(self) -> None:
        function = miner.FunctionRecord(
            name="vendor_transceive",
            signature="int vendor_transceive(void *dev, struct bufs *rx_bufs)",
            params=["dev", "rx_bufs"],
            start_line=1,
            body_start_line=2,
            end_line=6,
            lines=[
                "int vendor_transceive(void *dev, struct bufs *rx_bufs)\n",
                "{\n",
                "  for (i = 0; i < rx_bufs->count; i++) {\n",
                "    rx_bufs->buffers[i] = *(uint32_t *)(regs + 8);\n",
                "  }\n",
                "}\n",
            ],
        )
        candidates, _ = miner.scan_complex_body_ingress_candidates(
            [function], REGISTRY, confirmed_functions=set(), start_candidate_index=1
        )
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["candidate_source_buffer"], "rx_bufs")
        self.assertEqual(
            candidates[0]["allowed_source_labels"],
            ["MMIO_READ"],
        )
        self.assertFalse(candidates[0]["site_id"].startswith("site:"))

    def test_input_consumer_is_not_source_call_but_read_output_is_candidate(self) -> None:
        function = miner.FunctionRecord(
            name="network_task",
            signature="void network_task(void)",
            params=[],
            start_line=1,
            body_start_line=2,
            end_line=6,
            lines=[
                "void network_task(void)\n", "{\n",
                "  read(rx_buf, frame_len);\n",
                "  uip_icmp6_input(rx_buf, frame_len);\n",
                "  consume(rx_buf);\n", "}\n",
            ],
        )
        candidates, _ = miner.scan_semantic_callsite_source_candidates(
            [function], REGISTRY, confirmed_keys=set(), start_candidate_index=1
        )
        self.assertEqual([row["callee"] for row in candidates], ["read"])

    def test_dma_without_trusted_direction_is_candidate(self) -> None:
        facts = {
            "functions": [
                {
                    "name": "configure_dma_rx",
                    "entry": "0x2000",
                    "decompiled_c": (
                        "void configure_dma_rx(void) { DMA->PAR = USART->RDR; "
                        "DMA->M0AR = rx_buffer; DMA->NDTR = 128; /* RX */ }"
                    ),
                    "pcode_ops": [
                        {
                            "site_id": "site:00002000:00002010:1",
                            "mnemonic": "STORE",
                            "output": None,
                            "inputs": [
                                varnode("const:space", offset="0x1", constant=True),
                                varnode("const:dma_par", offset="0x40026008", constant=True),
                                varnode("const:usart_rdr", offset="0x40011024", constant=True),
                            ],
                        },
                        {
                            "site_id": "site:00002000:00002014:2",
                            "mnemonic": "STORE",
                            "output": None,
                            "inputs": [
                                varnode("const:space", offset="0x1", constant=True),
                                varnode("const:dma_m0ar", offset="0x4002600c", constant=True),
                                varnode("const:rx_buffer", offset="0x20001000", constant=True),
                            ],
                        },
                    ],
                }
            ]
        }
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["candidate_kind"], "dma_descriptor_candidate")
        self.assertEqual(candidates[0]["candidate_source_object_id"], "global:20001000:unknown")
        self.assertFalse(candidates[0]["static_bindings"]["direction_proven"])

    def test_dma_with_typed_direction_metadata_is_confirmed(self) -> None:
        facts = {
            "functions": [
                {
                    "name": "configure_channel",
                    "entry": "0x3000",
                    "decompiled_c": "void configure_channel(void) { DMA->PAR = periph; DMA->M0AR = buf; }",
                    "dma_metadata": {
                        "direction": "peripheral_to_memory",
                        "metadata_source": "svd",
                        "register_roles": [
                            {
                                "address": "0x40026008", "role": "peripheral_address",
                                "descriptor_id": "dma1_stream0",
                            },
                            {
                                "address": "0x4002600c", "role": "memory_destination",
                                "descriptor_id": "dma1_stream0",
                            },
                        ],
                    },
                    "pcode_ops": [
                        {
                            "site_id": "site:00003000:00003010:1", "mnemonic": "STORE", "output": None,
                            "inputs": [
                                varnode("const:space", offset="0x1", constant=True),
                                varnode("const:par", offset="0x40026008", constant=True),
                                varnode("const:peripheral", offset="0x40011024", constant=True),
                            ],
                        },
                        {
                            "site_id": "site:00003000:00003014:2", "mnemonic": "STORE", "output": None,
                            "inputs": [
                                varnode("const:space", offset="0x1", constant=True),
                                varnode("const:m0ar", offset="0x4002600c", constant=True),
                                varnode("const:buffer", offset="0x20002000", constant=True),
                            ],
                        },
                    ],
                }
            ]
        }
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(candidates, [])
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0]["label"], "DMA_BACKED_BUFFER")
        self.assertEqual(confirmed[0]["source_object_id"], "global:20002000:unknown")

    def test_integrated_dma_packet_pointer_plus_rx_start_is_confirmed(self) -> None:
        facts = {
            "hardware_profile": {
                "schema_version": "ct-mini-hardware-metadata-v2",
                "scope": "platform",
                "metadata_source": "svd",
                "platform_id": "test-integrated-radio",
                "registers": [
                    {
                        "address": "0x40001004",
                        "instance_base": "0x40001000",
                        "peripheral_instance": "RADIO",
                        "peripheral_type": "RADIO",
                        "role": "RX_START",
                    },
                    {
                        "address": "0x40001504",
                        "instance_base": "0x40001000",
                        "peripheral_instance": "RADIO",
                        "peripheral_type": "RADIO",
                        "role": "DMA_BUFFER_POINTER",
                    },
                ],
            },
            "functions": [{
                "name": "configure_receive",
                "function_id": "fn:00004000",
                "decompiled_c": "void configure_receive(void) { /* body omitted */ }",
                "pcode_ops": [
                    {
                        "site_id": "site:4000:4010:1",
                        "mnemonic": "STORE",
                        "output": None,
                        "inputs": [
                            varnode("const:s", offset="1", constant=True),
                            varnode("const:packetptr", offset="0x40001504", constant=True),
                            varnode(
                                "global:20003000",
                                offset="0x20003000",
                                constant=True,
                                address=True,
                                name="packet_buffer",
                            ),
                        ],
                    },
                    {
                        "site_id": "site:4000:4014:1",
                        "mnemonic": "STORE",
                        "output": None,
                        "inputs": [
                            varnode("const:s2", offset="1", constant=True),
                            varnode("const:rxen", offset="0x40001004", constant=True),
                            varnode("const:one", offset="1", constant=True),
                        ],
                    },
                ],
            }],
        }
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(candidates, [])
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(confirmed[0]["label"], "DMA_BACKED_BUFFER")
        self.assertEqual(
            confirmed[0]["proof"]["proof_kind"],
            "shared_packet_pointer_plus_rx_start",
        )
        self.assertEqual(
            confirmed[0]["source_object_id"],
            "global:20003000:unknown",
        )

    def test_shared_dma_packet_pointer_without_rx_start_is_not_source(self) -> None:
        facts = {
            "hardware_profile": {
                "schema_version": "ct-mini-hardware-metadata-v2",
                "scope": "platform",
                "metadata_source": "svd",
                "platform_id": "test-integrated-radio",
                "registers": [
                    {
                        "address": "0x40001000",
                        "instance_base": "0x40001000",
                        "peripheral_instance": "RADIO",
                        "peripheral_type": "RADIO",
                        "role": "TX_START",
                    },
                    {
                        "address": "0x40001504",
                        "instance_base": "0x40001000",
                        "peripheral_instance": "RADIO",
                        "peripheral_type": "RADIO",
                        "role": "DMA_BUFFER_POINTER",
                    },
                ],
            },
            "functions": [{
                "name": "configure_transmit",
                "function_id": "fn:00005000",
                "decompiled_c": "void configure_transmit(void) { /* body omitted */ }",
                "pcode_ops": [
                    {
                        "site_id": "site:5000:5010:1",
                        "mnemonic": "STORE",
                        "output": None,
                        "inputs": [
                            varnode("const:s", offset="1", constant=True),
                            varnode("const:packetptr", offset="0x40001504", constant=True),
                            varnode(
                                "global:20004000",
                                offset="0x20004000",
                                constant=True,
                                address=True,
                            ),
                        ],
                    },
                    {
                        "site_id": "site:5000:5014:1",
                        "mnemonic": "STORE",
                        "output": None,
                        "inputs": [
                            varnode("const:s2", offset="1", constant=True),
                            varnode("const:txen", offset="0x40001000", constant=True),
                            varnode("const:one", offset="1", constant=True),
                        ],
                    },
                ],
            }],
        }
        confirmed, _, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])

    def test_dma_direction_without_exact_register_roles_is_candidate(self) -> None:
        facts = {
            "functions": [{
                "name": "configure_channel", "function_id": "fn:00003000",
                "decompiled_c": "void configure_channel(void) { DMA->CCR = periph; DMA->IFCR = buf; }",
                "dma_metadata": {"direction": "peripheral_to_memory", "metadata_source": "svd"},
                "pcode_ops": [
                    {
                        "site_id": "site:3000:3010:1", "mnemonic": "STORE", "output": None,
                        "inputs": [varnode("const:s", offset="1", constant=True),
                                   varnode("const:a", offset="0x40026008", constant=True),
                                   varnode("const:p", offset="0x40011024", constant=True)],
                    },
                    {
                        "site_id": "site:3000:3014:1", "mnemonic": "STORE", "output": None,
                        "inputs": [varnode("const:s2", offset="1", constant=True),
                                   varnode("const:b", offset="0x4002600c", constant=True),
                                   varnode("const:r", offset="0x20002000", constant=True)],
                    },
                ],
            }]
        }
        confirmed, candidates, _, _, _ = miner.structured_mmio_and_dma_scan(
            facts, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertEqual(confirmed, [])
        self.assertEqual(len(candidates), 1)

    def test_null_actual_does_not_instantiate_body_summary(self) -> None:
        callee = mmio_facts("void receive(Regs *regs, char *dst) { *dst = regs->RDR; }")["functions"][0]
        callee.update({"name": "receive", "function_id": "fn:00001000"})
        caller = {
            "name": "caller", "function_id": "fn:00002000", "decompiled_c": "receive(regs, NULL);",
            "pcode_ops": [{
                "site_id": "site:2000:2010:1", "mnemonic": "CALL", "output": None,
                "inputs": [
                    varnode("const:target", offset="0x1000", constant=True),
                    varnode("param:2000:0", name="regs", parameter=True, slot=0),
                    varnode("const:null", offset="0x0", constant=True, address=True),
                ],
                "call": {"kind": "CALL", "target_function": "receive", "target_function_id": "fn:00001000"},
            }],
        }
        confirmed, _, _, _, _ = miner.structured_mmio_and_dma_scan(
            {"functions": [callee, caller]}, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertFalse(any(row["detection_kind"] == "high_pcode_body_summary_callsite" for row in confirmed))

    def test_ssa_null_actual_does_not_instantiate_body_summary(self) -> None:
        callee = mmio_facts("void receive(Regs *regs, char *dst) { *dst = regs->RDR; }")["functions"][0]
        callee.update({"name": "receive", "function_id": "fn:00001000"})
        null_value = varnode("reg:2000:20:4", name="p", value_id="value:null-copy")
        caller = {
            "name": "caller", "function_id": "fn:00002000", "decompiled_c": "p = 0; receive(regs, p);",
            "pcode_ops": [
                {
                    "site_id": "site:00002000:00002008:1", "mnemonic": "COPY", "output": null_value,
                    "inputs": [varnode("const:null", offset="0", constant=True)],
                },
                {
                    "site_id": "site:00002000:00002010:1", "mnemonic": "CALL", "output": None,
                    "inputs": [varnode("const:target", offset="0x1000", constant=True),
                               varnode("param:2000:0", name="regs", parameter=True, slot=0),
                               null_value],
                    "call": {"kind": "CALL", "target_function": "receive", "target_function_id": "fn:00001000"},
                },
            ],
        }
        confirmed, _, _, _, _ = miner.structured_mmio_and_dma_scan(
            {"functions": [callee, caller]}, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertFalse(any(row["detection_kind"] == "high_pcode_body_summary_callsite" for row in confirmed))

    def test_indirect_ssa_null_actual_does_not_instantiate_body_summary(self) -> None:
        callee = mmio_facts("void receive(Regs *regs, char *dst) { *dst = regs->RDR; }")["functions"][0]
        callee.update({"name": "receive", "function_id": "fn:00001000"})
        null_value = varnode("reg:2000:20:4", name="p", value_id="value:indirect-null")
        caller = {
            "name": "caller", "function_id": "fn:00002000", "decompiled_c": "p = 0; receive(regs, p);",
            "pcode_ops": [
                {
                    "site_id": "site:00002000:00002008:1", "mnemonic": "INDIRECT", "output": null_value,
                    "inputs": [varnode("const:null", offset="0", constant=True),
                               varnode("const:iop", offset="0x1234", constant=True)],
                },
                {
                    "site_id": "site:00002000:00002010:1", "mnemonic": "CALL", "output": None,
                    "inputs": [varnode("const:target", offset="0x1000", constant=True),
                               varnode("param:2000:0", name="regs", parameter=True, slot=0), null_value],
                    "call": {"kind": "CALL", "target_function": "receive", "target_function_id": "fn:00001000"},
                },
            ],
        }
        confirmed, _, _, _, _ = miner.structured_mmio_and_dma_scan(
            {"functions": [callee, caller]}, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertFalse(any(row["detection_kind"] == "high_pcode_body_summary_callsite" for row in confirmed))

    def test_duplicate_function_names_are_not_name_bound(self) -> None:
        first = mmio_facts("void receive(Regs *regs, char *dst) { *dst = regs->RDR; }")["functions"][0]
        first.update({"name": "receive", "function_id": "fn:00001000"})
        second = {"name": "receive", "function_id": "fn:00001100", "decompiled_c": "void receive(void) {}", "pcode_ops": []}
        caller = {
            "name": "caller", "function_id": "fn:00002000", "decompiled_c": "receive(regs, buf);",
            "pcode_ops": [{
                "site_id": "site:2000:2010:1", "mnemonic": "CALL", "output": None,
                "inputs": [varnode("const:t", offset="0x1000", constant=True),
                           varnode("param:2000:0", name="regs", parameter=True, slot=0),
                           varnode("param:2000:1", name="buf", parameter=True, slot=1)],
                "call": {"kind": "CALL", "target_function": "receive", "target_function_id": ""},
            }],
        }
        confirmed, _, _, _, _ = miner.structured_mmio_and_dma_scan(
            {"functions": [first, second, caller]}, REGISTRY, start_source_index=1, start_candidate_index=1
        )
        self.assertFalse(any(row["detection_kind"] == "high_pcode_body_summary_callsite" for row in confirmed))

    def test_body_summary_propagates_through_direct_wrapper(self) -> None:
        leaf = mmio_facts("void leaf(Regs *regs, char *dst) { *dst = regs->RDR; }")["functions"][0]
        leaf.update({"name": "leaf", "function_id": "fn:00001000"})
        wrapper = {
            "name": "wrapper", "function_id": "fn:00002000", "decompiled_c": "void wrapper(char *out) { leaf(regs, out); }",
            "pcode_ops": [{
                "site_id": "site:00002000:00002010:1", "mnemonic": "CALL", "output": None,
                "inputs": [
                    varnode("const:leaf", offset="0x1000", constant=True),
                    varnode("global:40010000", offset="0x40010000", address=True, name="regs"),
                    varnode("param:00002000:0", name="out", parameter=True, slot=0),
                ],
                "call": {"kind": "CALL", "target_function": "leaf", "target_function_id": "fn:00001000"},
            }],
        }
        top = {
            "name": "top", "function_id": "fn:00003000", "decompiled_c": "void top(char *packet) { wrapper(packet); }",
            "pcode_ops": [{
                "site_id": "site:00003000:00003010:1", "mnemonic": "CALL", "output": None,
                "inputs": [
                    varnode("const:wrapper", offset="0x2000", constant=True),
                    varnode("param:00003000:0", name="packet", parameter=True, slot=0),
                ],
                "call": {"kind": "CALL", "target_function": "wrapper", "target_function_id": "fn:00002000"},
            }],
        }
        confirmed, _, _, _, _ = miner.structured_mmio_and_dma_scan(
            {
                "functions": [leaf, wrapper, top],
                "register_metadata": [{"address": "0x40010000", "role": "DATA"}],
            }, REGISTRY,
            start_source_index=1, start_candidate_index=1,
        )
        top_rows = [
            row for row in confirmed
            if row["function"] == "top"
            and row["detection_kind"] == "high_pcode_body_summary_callsite"
        ]
        self.assertEqual(len(top_rows), 1)
        self.assertEqual(top_rows[0]["source_buffer"], "packet")
        self.assertEqual(top_rows[0]["source_site"], "direct CALL wrapper(packet)")

    def test_constant_named_object_binding_is_selected_for_callind_resolution(self) -> None:
        functions = [
            miner.FunctionRecord(
                name="neutral_initializer",
                signature="void neutral_initializer(void)",
                params=[],
                start_line=1,
                body_start_line=2,
                end_line=4,
                lines=[
                    "void neutral_initializer(void)\n",
                    "{\n",
                    '  global_object = framework_lookup("BUS_3");\n',
                    "}\n",
                ],
            )
        ]

        selected = miner.select_source_fact_functions(
            functions, REGISTRY, caller_depth=0
        )

        self.assertEqual(selected, ["neutral_initializer"])

    def test_verified_read_call_exposes_buffer_and_received_length(self) -> None:
        function = miner.FunctionRecord(
            name="task",
            signature="void task(char *buf, size_t n)",
            params=["buf", "n"],
            start_line=1,
            body_start_line=2,
            end_line=5,
            lines=[
                "void task(char *buf, size_t n)\n",
                "{\n",
                "  count = read(buf, n);\n",
                "  consume(buf, count);\n",
                "}\n",
            ],
        )
        candidates, _ = miner.scan_semantic_callsite_source_candidates(
            [function], REGISTRY, confirmed_keys=set(), start_candidate_index=1
        )
        facts = {"functions": [
            {
                "name": "task",
                "function_id": "fn:00004000",
                "pcode_ops": [{
                    "site_id": "site:00004000:00004010:1",
                    "mnemonic": "CALL",
                    "output": varnode(
                        "reg:4000:0:4", name="count", value_id="value:read-count"
                    ),
                    "inputs": [
                        varnode("const:read", offset="0x5000", constant=True),
                        varnode(
                            "param:00004000:0", name="buf", parameter=True, slot=0,
                            value_id="value:buf-pointer",
                        ),
                        varnode(
                            "param:00004000:1", name="n", parameter=True, slot=1
                        ),
                    ],
                    "call": {
                        "kind": "CALL",
                        "target_function": "read",
                        "target_function_id": "fn:00005000",
                    },
                }],
            },
            {"name": "read", "function_id": "fn:00005000", "pcode_ops": []},
        ]}
        enriched = miner.enrich_candidates_with_program_facts(candidates, facts)
        row = miner.heuristic_source_row(enriched[0], "SO0001")

        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(
            [output["role"] for output in row["source_outputs"]],
            ["output_buffer", "received_length"],
        )
        self.assertEqual(row["source_outputs"][0]["object_id"], "param:00004000:0")
        self.assertEqual(row["source_outputs"][1]["value_id"], "value:read-count")
        self.assertTrue(row["chain_ready"])

    def test_verified_read_without_call_output_exposes_only_buffer(self) -> None:
        candidate = miner.make_candidate(
            candidate_number=1,
            candidate_kind="semantic_callsite_source_candidate",
            label_hint="BYTE_STREAM_INGRESS",
            source_kind_hint="receive",
            function="task",
            plain_line=3,
            callee="read",
            source_site="read(buf, n)",
            candidate_source_buffer="buf",
            actual_args=["buf", "n"],
            known_facts=["candidate buffer is used after callsite: buf"],
            static_bindings={
                "source_actual_arg_index": 0,
                "semantic_callsite_category": "read_like_call",
            },
        )
        facts = {"functions": [
            {
                "name": "task",
                "function_id": "fn:00004000",
                "pcode_ops": [{
                    "site_id": "site:00004000:00004010:1",
                    "mnemonic": "CALL",
                    "output": None,
                    "inputs": [
                        varnode("const:read", offset="0x5000", constant=True),
                        varnode(
                            "param:00004000:0", name="buf", parameter=True, slot=0,
                            value_id="value:buf-pointer",
                        ),
                        varnode("param:00004000:1", name="n", parameter=True, slot=1),
                    ],
                    "call": {
                        "kind": "CALL",
                        "target_function": "read",
                        "target_function_id": "fn:00005000",
                    },
                }],
            },
            {"name": "read", "function_id": "fn:00005000", "pcode_ops": []},
        ]}
        enriched = miner.enrich_candidates_with_program_facts([candidate], facts)
        row = miner.heuristic_source_row(enriched[0], "SO0001")

        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(
            [output["role"] for output in row["source_outputs"]],
            ["output_buffer"],
        )

    def test_body_proved_read_summary_can_expose_multiple_outputs(self) -> None:
        callee = mmio_facts(
            "int read(Regs *regs, char *dst) { *dst = regs->RDR; return 1; }"
        )["functions"][0]
        callee.update({"name": "read", "function_id": "fn:00001000"})
        caller = {
            "name": "task",
            "function_id": "fn:00002000",
            "decompiled_c": "count = read(regs, packet);",
            "pcode_ops": [{
                "site_id": "site:00002000:00002010:1",
                "mnemonic": "CALL",
                "output": varnode(
                    "reg:2000:0:4", name="count", value_id="value:body-read-count"
                ),
                "inputs": [
                    varnode("const:read", offset="0x1000", constant=True),
                    varnode("global:40010000", offset="0x40010000", address=True),
                    varnode(
                        "param:00002000:0", name="packet", parameter=True, slot=0,
                        value_id="value:packet-pointer",
                    ),
                ],
                "call": {
                    "kind": "CALL",
                    "target_function": "read",
                    "target_function_id": "fn:00001000",
                },
            }],
        }
        confirmed, _, _, _, _ = miner.structured_mmio_and_dma_scan(
            {
                "functions": [callee, caller],
                "register_metadata": [{"address": "0x40010000", "role": "DATA"}],
            },
            REGISTRY,
            start_source_index=1,
            start_candidate_index=1,
        )
        rows = [
            row for row in confirmed
            if row["detection_kind"] == "high_pcode_body_summary_callsite"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            [output["role"] for output in rows[0]["source_outputs"]],
            ["output_buffer", "received_length"],
        )
        self.assertEqual(rows[0]["source_outputs"][1]["value_id"], "value:body-read-count")

    def test_source_output_singular_fields_remain_compatible(self) -> None:
        row = miner.confirmed_source_row(
            source_id="SO0001",
            detection_kind="test_source",
            confirmation_source="deterministic_test",
            label="BYTE_STREAM_INGRESS",
            source_kind="test_buffer",
            function="task",
            plain_line=3,
            source_site="read(buf, n)",
            source_buffer="buf",
            source_object_id="global:20001000:128",
            source_value_id="value:buf-pointer",
        )

        self.assertEqual(len(row["source_outputs"]), 1)
        self.assertEqual(row["source_output"], row["source_outputs"][0])
        self.assertEqual(row["source_object_id"], row["source_output"]["object_id"])
        self.assertEqual(row["source_value_id"], row["source_output"]["value_id"])
        self.assertTrue(row["chain_ready"])

    def test_compatibility_mode_does_not_directly_confirm_text_mmio(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "plain.c"
            sources = Path(tmp) / "sources.json"
            unconfirmed = Path(tmp) / "source_unconfirmed.json"
            corpus.write_text("void vendor_receive(char *dst)\n{\n  *dst = regs->RDR;\n}\n")
            proc = subprocess.run([
                sys.executable, str(ROOT / "scripts" / "build_source_artifacts.py"),
                "--input", str(corpus), "--sources-json", str(sources),
                "--source-unconfirmed-json", str(unconfirmed),
            ], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(sources.read_text())
            self.assertEqual(result["confirmed_sources"], [])

    def test_program_fact_enrichment_binds_every_candidate(self) -> None:
        facts = {
            "functions": [{
                "name": "task", "function_id": "fn:00004000", "pcode_ops": [
                    {
                        "site_id": "site:00004000:00004010:1", "mnemonic": "CALL",
                        "inputs": [varnode("const:a", constant=True), varnode("param:4000:0", name="buf_a", parameter=True, slot=0)],
                        "call": {"kind": "CALL", "target_function": "recv_a", "target_function_id": "fn:00005000"},
                    },
                    {
                        "site_id": "site:00004000:00004020:1", "mnemonic": "CALL",
                        "inputs": [varnode("const:b", constant=True), varnode("param:4000:1", name="buf_b", parameter=True, slot=1)],
                        "call": {"kind": "CALL", "target_function": "recv_b", "target_function_id": "fn:00006000"},
                    },
                ],
            }, {"name": "recv_a", "function_id": "fn:00005000", "pcode_ops": []},
               {"name": "recv_b", "function_id": "fn:00006000", "pcode_ops": []}],
        }
        candidates = [
            miner.make_candidate(
                candidate_number=1, candidate_kind="semantic_callsite_source_candidate",
                label_hint="BYTE_STREAM_INGRESS", source_kind_hint="receive",
                function="task", plain_line=1, callee="recv_a", source_site="recv_a(buf_a)",
                candidate_source_buffer="buf_a", actual_args=["buf_a"],
                static_bindings={"source_actual_arg_index": 0},
            ),
            miner.make_candidate(
                candidate_number=2, candidate_kind="semantic_callsite_source_candidate",
                label_hint="BYTE_STREAM_INGRESS", source_kind_hint="receive",
                function="task", plain_line=2, callee="recv_b", source_site="recv_b(buf_b)",
                candidate_source_buffer="buf_b", actual_args=["buf_b"],
                static_bindings={"source_actual_arg_index": 0},
            ),
        ]
        enriched = miner.enrich_candidates_with_program_facts(candidates, facts)
        self.assertEqual(
            [row["candidate_source_object_id"] for row in enriched],
            ["param:4000:0", "param:4000:1"],
        )

    def test_repeated_callee_candidates_bind_by_actual_argument(self) -> None:
        facts = {"functions": [
            {
                "name": "task", "function_id": "fn:00004000", "pcode_ops": [
                    {
                        "site_id": "site:00004000:00004010:1", "mnemonic": "CALL",
                        "inputs": [varnode("const:a", constant=True),
                                   varnode("param:4000:0", name="buf_a", parameter=True, slot=0)],
                        "call": {"kind": "CALL", "target_function": "recv", "target_function_id": "fn:00005000"},
                    },
                    {
                        "site_id": "site:00004000:00004020:1", "mnemonic": "CALL",
                        "inputs": [varnode("const:b", constant=True),
                                   varnode("param:4000:1", name="buf_b", parameter=True, slot=1)],
                        "call": {"kind": "CALL", "target_function": "recv", "target_function_id": "fn:00005000"},
                    },
                ],
            },
            {"name": "recv", "function_id": "fn:00005000", "pcode_ops": []},
        ]}
        candidates = [
            miner.make_candidate(
                candidate_number=index + 1, candidate_kind="semantic_callsite_source_candidate",
                label_hint="BYTE_STREAM_INGRESS", source_kind_hint="receive", function="task",
                plain_line=index + 1, callee="recv", source_site=f"recv({name})",
                candidate_source_buffer=name, actual_args=[name],
                static_bindings={"source_actual_arg_index": 0},
            )
            for index, name in enumerate(("buf_a", "buf_b"))
        ]
        enriched = miner.enrich_candidates_with_program_facts(candidates, facts)
        self.assertEqual(
            [row["site_id"] for row in enriched],
            ["site:00004000:00004010:1", "site:00004000:00004020:1"],
        )

    def test_repeated_callee_same_actual_remains_unbound(self) -> None:
        facts = {"functions": [
            {
                "name": "task", "function_id": "fn:00004000", "pcode_ops": [
                    {
                        "site_id": site, "mnemonic": "CALL",
                        "inputs": [varnode(f"const:{index}", constant=True),
                                   varnode(f"reg:4000:{index}:4", name="buf", value_id=f"value:buf:{index}")],
                        "call": {"kind": "CALL", "target_function": "recv", "target_function_id": "fn:00005000"},
                    }
                    for index, site in enumerate(("site:00004000:00004010:1", "site:00004000:00004020:1"))
                ],
            },
            {"name": "recv", "function_id": "fn:00005000", "pcode_ops": []},
        ]}
        candidates = [
            miner.make_candidate(
                candidate_number=index + 1, candidate_kind="semantic_callsite_source_candidate",
                label_hint="BYTE_STREAM_INGRESS", source_kind_hint="receive", function="task",
                plain_line=10 + index * 10, callee="recv", source_site="recv(buf)",
                candidate_source_buffer="buf", actual_args=["buf"],
                static_bindings={"source_actual_arg_index": 0},
            )
            for index in range(2)
        ]
        enriched = miner.enrich_candidates_with_program_facts(candidates, facts)
        self.assertTrue(all(not row["site_id"].startswith("site:") for row in enriched))

    def test_matching_call_counts_allow_ordinal_binding_across_renaming(self) -> None:
        facts = {"functions": [
            {
                "name": "task", "function_id": "fn:00004000", "pcode_ops": [
                    {
                        "site_id": "site:00004000:00004010:1", "mnemonic": "CALL",
                        "inputs": [varnode("const:a", constant=True),
                                   varnode("unique:a", name="first_renamed", value_id="value:first")],
                        "call": {"kind": "CALL", "target_function": "recv", "target_function_id": "fn:00005000"},
                    },
                    {
                        "site_id": "site:00004000:00004020:1", "mnemonic": "CALL",
                        "inputs": [varnode("const:b", constant=True),
                                   varnode("unique:b", name="second_renamed", value_id="value:second")],
                        "call": {"kind": "CALL", "target_function": "recv", "target_function_id": "fn:00005000"},
                    },
                ],
            },
            {"name": "recv", "function_id": "fn:00005000", "pcode_ops": []},
        ]}
        candidate = miner.make_candidate(
            candidate_number=1, candidate_kind="semantic_callsite_source_candidate",
            label_hint="BYTE_STREAM_INGRESS", source_kind_hint="receive", function="task",
            plain_line=20, callee="recv", source_site="recv(original_second)",
            candidate_source_buffer="original_second", actual_args=["original_second"],
            static_bindings={
                "source_actual_arg_index": 0,
                "callee_call_ordinal": 1,
                "callee_call_count": 2,
            },
        )
        enriched = miner.enrich_candidates_with_program_facts([candidate], facts)
        self.assertEqual(enriched[0]["site_id"], "site:00004000:00004020:1")


if __name__ == "__main__":
    unittest.main()
