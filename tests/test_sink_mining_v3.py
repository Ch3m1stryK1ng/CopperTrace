from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_sink_artifacts as sink  # noqa: E402


COPY_SPEC = {
    "kind": "primitive_memory_sink",
    "label": "COPY_SINK",
    "dst_arg": 0,
    "src_arg": 1,
    "len_arg": 2,
}


class SinkMiningV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_primitives = sink.PRIMITIVE_SINK_SPECS
        sink.PRIMITIVE_SINK_SPECS = {"memcpy": dict(COPY_SPEC)}

    def tearDown(self) -> None:
        sink.PRIMITIVE_SINK_SPECS = self.old_primitives

    @staticmethod
    def functions(code: str) -> list[sink.FunctionRecord]:
        return sink.parse_functions(code.splitlines(keepends=True))

    def test_call_scanner_ignores_comments_and_string_literals(self) -> None:
        code = (
            "void f(char *dst, char *src, int len)\n"
            "{\n"
            "  /* memcpy(fake, fake, 4); */\n"
            '  char *text = "memcpy(fake, fake, 8)";\n'
            "  memcpy(dst, src, len);\n"
            "}\n"
        )
        function = self.functions(code)[0]
        calls = sink.find_calls_in_function(function, {"memcpy"})
        self.assertEqual([call.expr for call in calls], ["memcpy(dst, src, len)"])

    def test_function_parser_does_not_require_blank_separator(self) -> None:
        code = "void a(void)\n{\n}\nvoid b(void)\n{\n}\n"
        self.assertEqual([function.name for function in self.functions(code)], ["a", "b"])

    def test_literal_format_with_dynamic_argument_remains_buffer_sink(self) -> None:
        call = sink.Callsite(
            callee="sprintf",
            args=["dst", '"%s"', "tainted"],
            function="f",
            line=3,
            expr='sprintf(dst, "%s", tainted)',
        )
        spec = {
            "kind": "primitive_format_sink",
            "label": "FORMAT_STRING_SINK",
            "dst_arg": 0,
            "fmt_arg": 1,
        }
        roles, vulnerable = sink.literal_format_output_roles(call, spec)
        self.assertEqual(roles["src_vararg_0"], "tainted")
        self.assertEqual(vulnerable, ["src_vararg_0"])

    def test_literal_format_keeps_varargs_separate(self) -> None:
        call = sink.Callsite(
            callee="snprintf",
            args=["dst", "size", '"%u.%u"', "first", "second"],
            function="f",
            line=3,
            expr='snprintf(dst, size, "%u.%u", first, second)',
        )
        spec = {
            "kind": "primitive_format_sink",
            "label": "FORMAT_STRING_SINK",
            "dst_arg": 0,
            "len_arg": 1,
            "fmt_arg": 2,
        }
        roles, vulnerable = sink.literal_format_output_roles(call, spec)
        self.assertEqual(roles["src_vararg_0"], "first")
        self.assertEqual(roles["src_vararg_1"], "second")
        self.assertEqual(vulnerable, ["src_vararg_0", "src_vararg_1", "len"])

    def test_peripheral_hint_requires_register_access_shape(self) -> None:
        self.assertFalse(sink.rhs_looks_peripheral_read("UART_history[i]"))
        self.assertTrue(sink.rhs_looks_peripheral_read("regs->SPI_RDR"))

    def test_wrapper_requires_all_sink_roles_to_map_to_formals(self) -> None:
        code = (
            "void wrap(char *dst, char *src, int len)\n"
            "{\n"
            "  char *p;\n"
            "  p = dst;\n"
            "  memcpy(p, src, len);\n"
            "}\n"
        )
        functions = self.functions(code)
        calls = sink.find_calls_in_function(functions[0], {"memcpy"})
        wrappers = sink.discover_wrappers(functions, calls)
        self.assertEqual(len(wrappers), 1)
        self.assertEqual(wrappers[0].roles["dst"], "arg0")
        self.assertEqual(wrappers[0].roles["src"], "arg1")
        self.assertEqual(wrappers[0].roles["len"], "arg2")

    def test_zero_score_pcode_binding_fails_closed(self) -> None:
        row = sink.confirmed_sink_row(
            sink_id="S1",
            detection_kind="primitive_callsite",
            confirmation_source="direct_api",
            label="COPY_SINK",
            sink_kind="primitive_memory_sink",
            callee="memcpy",
            function="f",
            plain_line=3,
            args=["4", "8", "16"],
            roles={"dst": "4", "src": "8", "len": "16"},
            expr="memcpy(4, 8, 16)",
            spec=COPY_SPEC,
        )
        nonconstant = {
            "object_id": "reg:f:0:4",
            "value_id": "value:f:0",
            "space": "register",
            "is_constant": False,
        }
        facts = {
            "functions": [
                {
                    "function_id": "fn:1",
                    "name": "f",
                    "pcode_ops": [
                        {
                            "mnemonic": "CALL",
                            "site_id": "site:1:2:3",
                            "instruction_address": "0x2",
                            "inputs": [{}, nonconstant, nonconstant, nonconstant],
                            "call": {
                                "target_function": "memcpy",
                                "target_function_id": "fn:memcpy",
                                "argument_object_ids": ["a", "b", "c"],
                                "argument_value_ids": ["va", "vb", "vc"],
                            },
                        }
                    ],
                }
            ]
        }
        sink.bind_sink_rows_to_program_facts([row], facts)
        self.assertEqual(row["binding_status"], "unresolved_callsite")
        self.assertNotIn("site_id", row)

    def test_tied_nonconstant_calls_fail_closed_without_ordinal_pairing(self) -> None:
        row = sink.confirmed_sink_row(
            sink_id="S1",
            detection_kind="primitive_callsite",
            confirmation_source="direct_api",
            label="COPY_SINK",
            sink_kind="primitive_memory_sink",
            callee="memcpy",
            function="f",
            plain_line=3,
            args=["dst", "src", "length"],
            roles={"dst": "dst", "src": "src", "len": "length"},
            expr="memcpy(dst, src, length)",
            spec=COPY_SPEC,
        )
        node = {
            "object_id": "reg:f:0:4",
            "value_id": "value:f:0",
            "space": "register",
            "is_constant": False,
        }
        calls = []
        for index in (1, 2):
            calls.append(
                {
                    "mnemonic": "CALL",
                    "site_id": f"site:1:{index}:1",
                    "instruction_address": hex(index),
                    "inputs": [{}, node, node, node],
                    "call": {
                        "target_function": "memcpy",
                        "target_function_id": "fn:memcpy",
                        "argument_object_ids": ["a", "b", "c"],
                        "argument_value_ids": ["va", "vb", "vc"],
                    },
                }
            )
        facts = {"functions": [{"function_id": "fn:1", "name": "f", "pcode_ops": calls}]}
        sink.bind_sink_rows_to_program_facts([row], facts)
        self.assertEqual(row["binding_status"], "ambiguous_callsite")
        self.assertNotIn("site_id", row)

    def test_argument_shape_handles_decompiler_call_reordering(self) -> None:
        dynamic = sink.confirmed_sink_row(
            sink_id="S1",
            detection_kind="primitive_callsite",
            confirmation_source="direct_api",
            label="COPY_SINK",
            sink_kind="primitive_memory_sink",
            callee="memcpy",
            function="f",
            plain_line=20,
            args=["dst", "src", "length"],
            roles={"dst": "dst", "src": "src", "len": "length"},
            expr="memcpy(dst, src, length)",
            spec=COPY_SPEC,
        )
        constant = sink.confirmed_sink_row(
            sink_id="S2",
            detection_kind="primitive_callsite",
            confirmation_source="direct_api",
            label="COPY_SINK",
            sink_kind="primitive_memory_sink",
            callee="memcpy",
            function="f",
            plain_line=10,
            args=["dst", "src", "4"],
            roles={"dst": "dst", "src": "src", "len": "4"},
            expr="memcpy(dst, src, 4)",
            spec=COPY_SPEC,
        )

        def pcode_node(name: str, *, constant_value: bool = False) -> dict:
            return {
                "object_id": f"{'const' if constant_value else 'reg'}:{name}:4",
                "value_id": f"value:{name}",
                "space": "const" if constant_value else "register",
                "high_name": name if not constant_value else "",
                "is_constant": constant_value,
            }

        calls = [
            {
                "mnemonic": "CALL",
                "site_id": "site:dynamic",
                "instruction_address": "0x10",
                "inputs": [{}, pcode_node("dst"), pcode_node("src"), pcode_node("length")],
                "call": {
                    "target_function": "memcpy",
                    "target_function_id": "fn:memcpy",
                    "argument_object_ids": ["d", "s", "n"],
                    "argument_value_ids": ["vd", "vs", "vn"],
                },
            },
            {
                "mnemonic": "CALL",
                "site_id": "site:constant",
                "instruction_address": "0x20",
                "inputs": [{}, pcode_node("dst"), pcode_node("src"), pcode_node("4", constant_value=True)],
                "call": {
                    "target_function": "memcpy",
                    "target_function_id": "fn:memcpy",
                    "argument_object_ids": ["d", "s", "c"],
                    "argument_value_ids": ["vd", "vs", "vc"],
                },
            },
        ]
        facts = {"functions": [{"function_id": "fn:1", "name": "f", "pcode_ops": calls}]}
        sink.bind_sink_rows_to_program_facts([dynamic, constant], facts)
        self.assertEqual(constant["site_id"], "site:constant")
        self.assertEqual(dynamic["site_id"], "site:dynamic")

    def test_strict_registry_has_no_framework_name_summaries(self) -> None:
        registry = sink.load_sink_registry(sink.DEFAULT_REGISTRY_PATH)
        self.assertEqual(registry["framework_sinks"], {})
        self.assertFalse(registry["pattern_sinks"])
        self.assertFalse(registry["dispatch_patterns"])
        primitive_names = set(registry["primitive_sinks"])
        self.assertNotIn("net_buf_simple_pull", primitive_names)
        self.assertNotIn("net_buf_simple_add_mem", primitive_names)
        self.assertNotIn("sys_mem_swap", primitive_names)

    def test_audit_only_heuristic_never_becomes_a_startpoint(self) -> None:
        startpoints, audit_rows, methods = sink.partition_audit_only_heuristics(
            [
                {"recognition_method": "paired_buffer_state", "site_id": "a"},
                {"recognition_method": "variable_address_store", "site_id": "b"},
            ],
            [
                {"id": "paired_buffer_state", "enabled": True},
                {
                    "id": "variable_address_store",
                    "enabled": False,
                    "audit_enabled": True,
                    "audit_only": True,
                },
            ],
        )
        self.assertEqual([row["site_id"] for row in startpoints], ["a"])
        self.assertEqual([row["site_id"] for row in audit_rows], ["b"])
        self.assertFalse(audit_rows[0]["eligible_for_bfs_rda"])
        self.assertEqual(methods, {"variable_address_store"})

    def test_field_update_has_only_dst_and_value_roles(self) -> None:
        code = (
            "void update(struct channel *channel, unsigned char *data)\n"
            "{\n"
            "  unsigned short credits;\n"
            "  memcpy(&credits, data + 5, 2);\n"
            "  channel->peer.credits = credits + channel->peer.credits;\n"
            "}\n"
        )
        rows, _annotations, _next_sink = sink.detect_field_update_store_sinks(
            self.functions(code), start_sink_index=1
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["decision"], "ACCEPT_HEURISTIC")
        self.assertEqual(rows[0]["vulnerable_parameter_roles"], ["dst", "value"])
        self.assertEqual(set(rows[0]["roles"]), {"dst", "value"})

    @staticmethod
    def field_update_row() -> dict:
        return sink.confirmed_sink_row(
            sink_id="S1",
            detection_kind="field_update_store",
            confirmation_source="deterministic_field_update_store",
            label="STORE_SINK",
            sink_kind="field_update_store_sink",
            callee="update",
            function="update",
            plain_line=5,
            args=["channel", "data"],
            roles={
                "dst": "channel->peer.credits",
                "value": "credits + channel->peer.credits",
            },
            expr="channel->peer.credits = credits + channel->peer.credits",
            vulnerable_roles=["dst", "value"],
            extra={
                "decision": "ACCEPT_HEURISTIC",
                "site_id": "textsite:update:5:field-update",
                "copied_local": "credits",
            },
        )

    @staticmethod
    def store_facts(*, source_name: str = "credits", store_count: int = 1) -> dict:
        source = {
            "object_id": f"stack:{source_name}",
            "value_id": f"value:{source_name}",
            "high_name": source_name,
            "is_constant": False,
        }
        old_value = {
            "object_id": "reg:old",
            "value_id": "value:old",
            "high_name": "old_credits",
            "is_constant": False,
        }
        sum_value = {
            "object_id": "reg:sum",
            "value_id": "value:sum",
            "high_name": "UNNAMED",
            "is_constant": False,
        }
        address = {
            "object_id": "unique:field-address",
            "value_id": "value:field-address",
            "high_name": "channel",
            "is_constant": False,
        }
        space = {
            "object_id": "const:space",
            "value_id": "const:space",
            "high_name": "",
            "is_constant": True,
        }
        ops = [
            {
                "mnemonic": "INT_ADD",
                "site_id": "site:update:add",
                "instruction_address": "0x100",
                "output": sum_value,
                "inputs": [source, old_value],
            }
        ]
        for index in range(store_count):
            ops.append(
                {
                    "mnemonic": "STORE",
                    "site_id": f"site:update:store:{index}",
                    "instruction_address": hex(0x102 + index * 2),
                    "output": None,
                    "inputs": [space, address, sum_value],
                }
            )
        return {
            "functions": [
                {
                    "function_id": "fn:update",
                    "name": "update",
                    "pcode_ops": ops,
                }
            ]
        }

    def test_unique_int_add_store_binds_field_update(self) -> None:
        row = self.field_update_row()
        sink.bind_sink_rows_to_program_facts([row], self.store_facts())

        self.assertEqual(row["binding_status"], "verified_high_pcode_store")
        self.assertEqual(row["function_id"], "fn:update")
        self.assertEqual(row["site_id"], "site:update:store:0")
        self.assertEqual(row["text_site_id"], "textsite:update:5:field-update")
        parameters = {item["role"]: item for item in row["vulnerable_parameters"]}
        self.assertEqual(parameters["dst"]["object_id"], "unique:field-address")
        self.assertEqual(parameters["dst"]["value_id"], "value:field-address")
        self.assertEqual(parameters["value"]["object_id"], "reg:sum")
        self.assertEqual(parameters["value"]["value_id"], "value:sum")

    def test_store_binding_with_wrong_high_name_fails_closed(self) -> None:
        row = self.field_update_row()
        sink.bind_sink_rows_to_program_facts(
            [row], self.store_facts(source_name="unrelated_value")
        )

        self.assertEqual(row["binding_status"], "unresolved_store_binding")
        self.assertEqual(row["site_id"], "textsite:update:5:field-update")
        self.assertNotIn("function_id", row)
        self.assertNotIn("role_bindings", row)

    def test_ambiguous_store_binding_fails_closed(self) -> None:
        row = self.field_update_row()
        sink.bind_sink_rows_to_program_facts([row], self.store_facts(store_count=2))

        self.assertEqual(row["binding_status"], "ambiguous_store_binding")
        self.assertEqual(row["store_binding_candidate_count"], 2)
        self.assertEqual(row["site_id"], "textsite:update:5:field-update")
        self.assertNotIn("function_id", row)
        self.assertNotIn("role_bindings", row)

    def test_loop_copy_binds_only_when_value_and_destination_match(self) -> None:
        row = sink.confirmed_sink_row(
            sink_id="S2",
            detection_kind="loop_copy",
            confirmation_source="generalized_structural_heuristic",
            label="COPY_SINK",
            sink_kind="structural_heuristic_sink_startpoint",
            callee="update",
            function="update",
            plain_line=8,
            args=["channel", "credits"],
            roles={"dst": "channel[i]", "src": "credits[i]"},
            expr="channel[i] = credits[i]",
            vulnerable_roles=["dst", "src"],
            extra={"decision": "ACCEPT_HEURISTIC", "site_id": "textsite:loop"},
        )
        sink.bind_sink_rows_to_program_facts([row], self.store_facts())

        self.assertEqual(row["binding_status"], "verified_high_pcode_store")
        self.assertEqual(row["site_id"], "site:update:store:0")
        parameters = {item["role"]: item for item in row["vulnerable_parameters"]}
        self.assertEqual(parameters["dst"]["object_id"], "unique:field-address")
        self.assertEqual(parameters["src"]["value_id"], "value:sum")


if __name__ == "__main__":
    unittest.main()
