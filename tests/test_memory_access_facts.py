import unittest

from scripts.memory_access_facts import (
    MemoryAccessFactIndex,
    RegionRelation,
    region_relation,
)


def static_object(
    object_id: str,
    *,
    base_object_id: str | None = None,
    field_path: list[str] | None = None,
) -> dict:
    return {
        "node_id": object_id,
        "object_id": object_id,
        "base_object_id": base_object_id or object_id,
        "storage_kind": "STATIC_WRITABLE_DATA",
        "identity_kind": "ELF_SYMBOL_CONTAINMENT",
        "strict_region_eligible": True,
        "writable": True,
        "is_stack": False,
        "is_rom": False,
        "field_path": list(field_path or []),
    }


def access_edge(
    kind: str,
    *,
    site_id: str,
    function_id: str,
    object_id: str,
    base_object_id: str | None = None,
    value_id: str,
    offset: int | None = 0,
    extent: int | None = 1,
    selector_terms: list[dict] | None = None,
    field_path: list[str] | None = None,
    deterministic_context_ids: list[str] | None = None,
    context_ids: list[str] | None = None,
    candidate_class: str = "EXACT_HIGH_PCODE_MEMORY_ACCESS",
) -> dict:
    assert kind in {"OBJECT_WRITE", "OBJECT_READ"}
    return {
        "edge_id": f"edge:{site_id}",
        "edge_kind": kind,
        "site_id": site_id,
        "function_id": function_id,
        "object_id": object_id,
        "base_object_id": base_object_id or object_id,
        "value_id": value_id,
        "value_object_id": f"atom-object:{value_id}",
        "access_width": extent or 0,
        "address_provenance": "HIGH_PCODE_EXACT_ADDRESS",
        "region_id": f"region:{site_id}",
        "region_offset": offset,
        "region_extent": extent,
        "region": {
            "object_id": object_id,
            "base_object_id": base_object_id or object_id,
            "offset": offset,
            "extent": extent,
            "selector_terms": list(selector_terms or []),
            "field_path": list(field_path or []),
        },
        "field_path": list(field_path or []),
        "candidate_class": candidate_class,
        "deterministic_context_ids": list(
            deterministic_context_ids or []
        ),
        "context_ids": list(context_ids or []),
        "analysis_blockers": [],
    }


class MemoryAccessFactIndexTests(unittest.TestCase):
    def test_concrete_object_write_and_read_become_facts(self) -> None:
        object_id = "obj:symbol:20000100:buffer"
        objects = [static_object(object_id)]
        edges = [
            access_edge(
                "OBJECT_WRITE",
                site_id="site:1000:1010",
                function_id="fn:1000",
                object_id=object_id,
                value_id="value:written",
                offset=4,
                extent=2,
            ),
            access_edge(
                "OBJECT_READ",
                site_id="site:2000:2010",
                function_id="fn:2000",
                object_id=object_id,
                value_id="value:loaded",
                offset=4,
                extent=2,
            ),
        ]

        index = MemoryAccessFactIndex.from_exact_edges(edges, objects)

        self.assertEqual(len(index.write_facts), 1)
        self.assertEqual(len(index.read_facts), 1)
        write = index.write_facts[0]
        read = index.read_facts[0]
        self.assertEqual(write.access_kind, "WRITE")
        self.assertEqual(read.access_kind, "READ")
        self.assertEqual(write.stored_atom_id, "value:written")
        self.assertEqual(read.loaded_atom_id, "value:loaded")
        self.assertEqual(write.aggregate_object_id, object_id)
        self.assertEqual(read.aggregate_object_id, object_id)
        self.assertIs(index.fact_by_site["site:1000:1010"], write)
        self.assertIs(index.fact_by_site["site:2000:2010"], read)
        self.assertEqual(index.writes_by_object[object_id], [write])
        self.assertEqual(index.reads_by_object[object_id], [read])
        self.assertEqual(
            write.to_dict(),
            {
                "access_kind": "WRITE",
                "site_id": "site:1000:1010",
                "function_id": "fn:1000",
                "object_id": object_id,
                "aggregate_object_id": object_id,
                "base_object_id": object_id,
                "stored_atom_id": "value:written",
                "loaded_atom_id": "",
                "region_offset": 4,
                "region_extent": 2,
                "selector_terms": [],
                "field_path": [],
                "address_provenance": "HIGH_PCODE_EXACT_ADDRESS",
                "deterministic_context_ids": [],
                "context_ids": [],
            },
        )

    def test_region_relation_distinguishes_exact_may_and_disjoint(self) -> None:
        object_id = "obj:symbol:20000180:ring"
        objects = [static_object(object_id)]
        edges = [
            access_edge(
                "OBJECT_WRITE",
                site_id="site:1100:1110",
                function_id="fn:1100",
                object_id=object_id,
                value_id="value:write",
                offset=0,
                extent=4,
            ),
            access_edge(
                "OBJECT_READ",
                site_id="site:1200:1210",
                function_id="fn:1200",
                object_id=object_id,
                value_id="value:overlap",
                offset=2,
                extent=4,
            ),
            access_edge(
                "OBJECT_READ",
                site_id="site:1300:1310",
                function_id="fn:1300",
                object_id=object_id,
                value_id="value:disjoint",
                offset=16,
                extent=1,
            ),
            access_edge(
                "OBJECT_READ",
                site_id="site:1400:1410",
                function_id="fn:1400",
                object_id=object_id,
                value_id="value:dynamic",
                offset=None,
                extent=1,
                selector_terms=[
                    {"selector_value_id": "value:tail", "stride": 1}
                ],
            ),
        ]

        index = MemoryAccessFactIndex.from_exact_edges(edges, objects)
        write = index.write_facts[0]
        reads = {fact.loaded_atom_id: fact for fact in index.read_facts}

        self.assertEqual(
            region_relation(write, reads["value:overlap"]),
            RegionRelation.EXACT_OVERLAP,
        )
        self.assertEqual(
            region_relation(write, reads["value:disjoint"]),
            RegionRelation.DISJOINT,
        )
        self.assertEqual(
            region_relation(write, reads["value:dynamic"]),
            RegionRelation.MAY_OVERLAP,
        )

    def test_dynamic_selectors_of_one_buffer_share_aggregate_object(self) -> None:
        base_id = "obj:symbol:20000200:ring"
        head_id = f"{base_id}:selector:head"
        tail_id = f"{base_id}:selector:tail"
        objects = [
            static_object(base_id),
            static_object(head_id, base_object_id=base_id),
            static_object(tail_id, base_object_id=base_id),
        ]
        edges = [
            access_edge(
                "OBJECT_WRITE",
                site_id="site:3000:3010",
                function_id="fn:3000",
                object_id=head_id,
                base_object_id=base_id,
                value_id="value:incoming",
                offset=None,
                selector_terms=[
                    {"selector_value_id": "value:head", "stride": 1}
                ],
            ),
            access_edge(
                "OBJECT_READ",
                site_id="site:4000:4010",
                function_id="fn:4000",
                object_id=tail_id,
                base_object_id=base_id,
                value_id="value:consumed",
                offset=None,
                selector_terms=[
                    {"selector_value_id": "value:tail", "stride": 1}
                ],
            ),
        ]

        index = MemoryAccessFactIndex.from_exact_edges(edges, objects)

        write = index.write_facts[0]
        read = index.read_facts[0]
        self.assertEqual(write.aggregate_object_id, base_id)
        self.assertEqual(read.aggregate_object_id, base_id)
        self.assertEqual(index.writes_by_object[base_id], [write])
        self.assertEqual(index.reads_by_object[base_id], [read])
        self.assertNotEqual(write.selector_terms, read.selector_terms)

    def test_explicit_struct_fields_remain_distinct_objects(self) -> None:
        base_id = "obj:symbol:20000300:state"
        length_id = f"{base_id}:field:length"
        cursor_id = f"{base_id}:field:cursor"
        objects = [
            static_object(base_id),
            static_object(
                length_id,
                base_object_id=base_id,
                field_path=["field:length"],
            ),
            static_object(
                cursor_id,
                base_object_id=base_id,
                field_path=["field:cursor"],
            ),
        ]
        edges = [
            access_edge(
                "OBJECT_WRITE",
                site_id="site:5000:5010",
                function_id="fn:5000",
                object_id=length_id,
                base_object_id=base_id,
                value_id="value:length",
                field_path=["field:length"],
            ),
            access_edge(
                "OBJECT_READ",
                site_id="site:6000:6010",
                function_id="fn:6000",
                object_id=cursor_id,
                base_object_id=base_id,
                value_id="value:cursor",
                field_path=["field:cursor"],
            ),
        ]

        index = MemoryAccessFactIndex.from_exact_edges(edges, objects)

        write = index.write_facts[0]
        read = index.read_facts[0]
        self.assertEqual(write.aggregate_object_id, length_id)
        self.assertEqual(read.aggregate_object_id, cursor_id)
        self.assertNotEqual(write.aggregate_object_id, read.aggregate_object_id)
        self.assertNotIn(cursor_id, index.writes_by_object)
        self.assertNotIn(length_id, index.reads_by_object)

    def test_ineligible_object_kinds_record_blockers_without_facts(self) -> None:
        stack_id = "obj:stack:fn:7000:local"
        call_result_id = "obj:call-result:site:8000:8010"
        unresolved_id = "obj:unresolved:pointer"
        objects = [
            {
                "node_id": stack_id,
                "object_id": stack_id,
                "base_object_id": stack_id,
                "storage_kind": "STACK_LOCAL",
                "is_stack": True,
                "strict_region_eligible": False,
            },
            {
                "node_id": call_result_id,
                "object_id": call_result_id,
                "base_object_id": call_result_id,
                "storage_kind": "CALL_RESULT_OBJECT",
                "identity_kind": "CALLSITE_CONTEXT_OBJECT",
                "strict_region_eligible": False,
            },
            {
                "node_id": unresolved_id,
                "object_id": unresolved_id,
                "base_object_id": "",
                "storage_kind": "UNRESOLVED",
                "identity_kind": "UNRESOLVED_POINTER",
                "strict_region_eligible": False,
            },
        ]
        edges = [
            access_edge(
                "OBJECT_WRITE",
                site_id="site:7000:7010",
                function_id="fn:7000",
                object_id=stack_id,
                value_id="value:stack",
            ),
            access_edge(
                "OBJECT_READ",
                site_id="site:8000:8020",
                function_id="fn:8000",
                object_id=call_result_id,
                value_id="value:call-result",
            ),
            access_edge(
                "OBJECT_WRITE",
                site_id="site:9000:9010",
                function_id="fn:9000",
                object_id=unresolved_id,
                value_id="value:unknown",
            ),
        ]

        index = MemoryAccessFactIndex.from_exact_edges(edges, objects)

        self.assertEqual(index.write_facts, [])
        self.assertEqual(index.read_facts, [])
        self.assertEqual(index.writes_by_object, {})
        self.assertEqual(index.reads_by_object, {})
        self.assertEqual(index.fact_by_site, {})
        self.assertEqual(
            {
                (row["site_id"], row["reason"])
                for row in index.blockers
            },
            {
                ("site:7000:7010", "ineligible_stack_object"),
                ("site:8000:8020", "ineligible_call_result_object"),
                ("site:9000:9010", "unresolved_memory_object"),
            },
        )

    def test_call_and_xref_without_concrete_memory_op_make_no_facts(self) -> None:
        object_id = "obj:symbol:20000400:data"
        objects = [static_object(object_id)]
        non_access_edges = [
            {
                "edge_id": "call:site:a000:a010",
                "edge_kind": "CALL",
                "site_id": "site:a000:a010",
                "function_id": "fn:a000",
                "src_node_id": "fn:a000",
                "dst_node_id": "fn:b000",
                "argument_object_ids": [object_id],
            },
            {
                "edge_id": "xref:site:c000:c010",
                "edge_kind": "XREF",
                "site_id": "site:c000:c010",
                "function_id": "fn:c000",
                "object_id": object_id,
            },
        ]

        index = MemoryAccessFactIndex.from_exact_edges(non_access_edges, objects)

        self.assertEqual(index.write_facts, [])
        self.assertEqual(index.read_facts, [])
        self.assertEqual(index.fact_by_site, {})
        self.assertEqual(index.blockers, [])

    def test_context_evidence_is_kept_separate(self) -> None:
        object_id = "obj:symbol:20000500:data"
        edge = access_edge(
            "OBJECT_WRITE",
            site_id="site:d000:d010",
            function_id="fn:d000",
            object_id=object_id,
            value_id="value:data",
            deterministic_context_ids=["ctx:isr"],
            context_ids=["ctx:isr", "ctx:name-rx-worker"],
        )

        index = MemoryAccessFactIndex.from_exact_edges(
            [edge], [static_object(object_id)]
        )

        fact = index.write_facts[0]
        self.assertEqual(fact.deterministic_context_ids, ("ctx:isr",))
        self.assertEqual(fact.context_ids, ("ctx:name-rx-worker",))

    def test_non_exact_class_and_missing_region_or_atom_are_blocked(self) -> None:
        object_id = "obj:symbol:20000600:data"
        objects = [static_object(object_id)]
        edges = [
            access_edge(
                "OBJECT_WRITE",
                site_id="site:e000:e010",
                function_id="fn:e000",
                object_id=object_id,
                value_id="value:heuristic",
                candidate_class="HEURISTIC_MEMORY_ACCESS",
            ),
            access_edge(
                "OBJECT_READ",
                site_id="site:e000:e020",
                function_id="fn:e000",
                object_id=object_id,
                value_id="",
                offset=None,
                extent=None,
            ),
        ]

        index = MemoryAccessFactIndex.from_exact_edges(edges, objects)

        self.assertEqual(index.write_facts, [])
        self.assertEqual(index.read_facts, [])
        reasons = {
            (row["site_id"], row["reason"]) for row in index.blockers
        }
        self.assertIn(
            (
                "site:e000:e010",
                "memory_access_candidate_class_not_exact",
            ),
            reasons,
        )
        self.assertIn(
            ("site:e000:e020", "concrete_access_value_atom_missing"),
            reasons,
        )
        self.assertIn(
            ("site:e000:e020", "concrete_access_region_offset_missing"),
            reasons,
        )
        self.assertIn(
            ("site:e000:e020", "concrete_access_region_extent_missing"),
            reasons,
        )


if __name__ == "__main__":
    unittest.main()
