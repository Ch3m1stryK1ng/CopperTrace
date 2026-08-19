"""Core data models for the RQ1 source/sink recovery pipeline.

Defines the label taxonomy, intermediate representations, and output formats
that flow between pipeline stages (M0-M9, VS0-VS5).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ── Source Labels (VS0, VS2, VS3) ────────────────────────────────────────────


class SourceLabel(str, Enum):
    """Source label taxonomy — where attacker-controlled data enters firmware."""

    MMIO_READ = "MMIO_READ"
    ISR_MMIO_READ = "ISR_MMIO_READ"
    ISR_FILLED_BUFFER = "ISR_FILLED_BUFFER"
    DMA_BACKED_BUFFER = "DMA_BACKED_BUFFER"
    BYTE_STREAM_INGRESS = "BYTE_STREAM_INGRESS"
    CONTROL_STATE = "CONTROL_STATE"
    SENSOR_INPUT = "SENSOR_INPUT"


# ── Sink Labels (VS1, VS4, VS5) ─────────────────────────────────────────────


class SinkLabel(str, Enum):
    """Sink label taxonomy — where data is consumed unsafely."""

    COPY_SINK = "COPY_SINK"
    MEMSET_SINK = "MEMSET_SINK"
    STORE_SINK = "STORE_SINK"
    LOOP_WRITE_SINK = "LOOP_WRITE_SINK"
    FORMAT_STRING_SINK = "FORMAT_STRING_SINK"
    FUNC_PTR_SINK = "FUNC_PTR_SINK"
    LIFETIME_SINK = "LIFETIME_SINK"


# ── Memory Map (M1) ─────────────────────────────────────────────────────────


@dataclass
class MemoryRegion:
    """A contiguous memory region in the firmware's address space."""

    name: str  # "FLASH", "SRAM", "PERIPHERAL"
    base: int
    size: int
    permissions: str  # "r", "rw", "rx", "rwx"
    kind: str  # "flash", "sram", "mmio"


@dataclass
class MemoryMap:
    """Memory layout for a loaded firmware binary (Stage 1 output)."""

    binary_path: str
    arch: str  # "ARM:LE:32:Cortex"
    base_address: int
    entry_point: int
    regions: List[MemoryRegion] = field(default_factory=list)
    vector_table_addr: int = 0
    hypotheses_source: str = "vector_table"  # "vector_table" | "elf_segments" | "heuristic"
    isr_handler_addrs: List[int] = field(default_factory=list)  # From vector table


# ── Memory Access Index (M2) ────────────────────────────────────────────────


@dataclass
class MemoryAccess:
    """A single load or store instruction extracted from p-code."""

    address: int  # Instruction address
    kind: str  # "load" | "store"
    width: int  # bytes: 1, 2, 4
    target_addr: Optional[int] = None  # Resolved target if statically known
    base_provenance: str = "UNKNOWN"  # "CONST", "GLOBAL_PTR", "STACK_PTR", "ARG"
    in_isr: bool = False
    function_name: str = ""
    function_addr: int = 0


@dataclass
class MemoryAccessIndex:
    """Index of all memory accesses in a binary (Stage 2 output)."""

    binary_path: str
    accesses: List[MemoryAccess] = field(default_factory=list)
    mmio_accesses: List[MemoryAccess] = field(default_factory=list)
    isr_functions: List[str] = field(default_factory=list)
    typed_bases: Dict[int, str] = field(default_factory=dict)
    global_symbol_table: Dict[str, int] = field(default_factory=dict)
    # Maps global/static symbol_name -> SRAM address (Stage 2 symbol enumeration)
    # Maps base_addr → peripheral_type, e.g. {0x40013800: "USART_TypeDef"}
    decompiled_cache: Dict[str, str] = field(default_factory=dict)
    # Maps function_name → decompiled C code (populated during Stage 2)
    function_locator_index: Dict[str, Any] = field(default_factory=dict)
    # Lightweight Stage-2 function locator index for later review-time lookup.
    stage2_degraded: bool = False
    stage2_degraded_reason: str = ""
    stage2_degraded_metadata: Dict[str, Any] = field(default_factory=dict)


# ── Candidates (Stage 3/4 output) ───────────────────────────────────────────


@dataclass
class EvidenceItem:
    """A piece of static evidence supporting a candidate label."""

    evidence_id: str  # "E1", "E2", etc.
    kind: str  # "SITE", "DEF", "GUARD", "SLICE_BACK", "XREF"
    text: str  # Instruction or decompiler text
    address: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceCandidate:
    """A candidate source location before LLM proposal."""

    address: int
    function_name: str
    preliminary_label: SourceLabel
    evidence: List[EvidenceItem] = field(default_factory=list)
    confidence_score: float = 0.0
    facts: Dict[str, Any] = field(default_factory=dict)
    needs_supervision: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    supervision_priority: float = 0.0
    supervision_checkpoint_hint: str = ""
    supervision_contract_source: str = ""


@dataclass
class SinkCandidate:
    """A candidate sink location before LLM proposal."""

    address: int
    function_name: str
    preliminary_label: SinkLabel
    evidence: List[EvidenceItem] = field(default_factory=list)
    confidence_score: float = 0.0
    facts: Dict[str, Any] = field(default_factory=dict)
    needs_supervision: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    supervision_priority: float = 0.0
    supervision_checkpoint_hint: str = ""
    supervision_contract_source: str = ""


# ── Evidence Packs (M5) ─────────────────────────────────────────────────────


@dataclass
class EvidencePack:
    """Complete evidence bundle for one candidate, sent to LLM proposer."""

    pack_id: str  # stable hash-based ID
    candidate_hint: str  # "MMIO_READ", "COPY_SINK", etc.
    binary_path: str
    address: int
    function_name: str
    facts: Dict[str, Any] = field(default_factory=dict)
    evidence: List[EvidenceItem] = field(default_factory=list)
    created_at: str = ""
    needs_supervision: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    supervision_priority: float = 0.0
    supervision_checkpoint_hint: str = ""
    supervision_contract_source: str = ""


# ── LLM Proposals (M6) ──────────────────────────────────────────────────────


@dataclass
class LLMProposal:
    """LLM's proposed label assignment for a candidate."""

    pack_id: str
    label: str  # SourceLabel or SinkLabel value
    address: int
    function_name: str
    claims: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0  # 0.0-1.0
    evidence_refs: List[str] = field(default_factory=list)  # ["E1", "E2"]
    notes: str = ""
    needs_supervision: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    supervision_priority: float = 0.0
    supervision_checkpoint_hint: str = ""
    supervision_contract_source: str = ""


# ── Verification Obligations (M7) ───────────────────────────────────────────


class ObligationStatus(str, Enum):
    """Status of a single verification obligation."""

    PENDING = "pending"
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    UNKNOWN = "unknown"


@dataclass
class Obligation:
    """A static-analysis check that must pass to confirm an LLM proposal."""

    obligation_id: str  # "O_MMIO_1", "O_COPY_2"
    kind: str  # "addr_range", "const_base_trace", "isr_reachable", etc.
    description: str
    required: bool = True  # False = strengthening (optional)
    status: ObligationStatus = ObligationStatus.PENDING
    evidence: str = ""


class VerificationVerdict(str, Enum):
    """Final verdict after all obligations are checked."""

    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


@dataclass
class VerifiedLabel:
    """Final result: an LLM proposal that has been checked by the verifier."""

    pack_id: str
    proposal: LLMProposal
    obligations: List[Obligation] = field(default_factory=list)
    verdict: VerificationVerdict = VerificationVerdict.UNKNOWN
    final_label: Optional[str] = None
    needs_supervision: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    supervision_priority: float = 0.0
    supervision_checkpoint_hint: str = ""
    supervision_contract_source: str = ""


# ── Evaluation (M0/M9) ──────────────────────────────────────────────────────


@dataclass
class GroundTruthEntry:
    """A ground-truth label for evaluation."""

    binary_stem: str
    label: str  # SourceLabel or SinkLabel value
    address: Optional[int] = None
    function_name: str = ""
    notes: str = ""
    pipeline_label_hint: str = ""  # optional: pipeline label that counts as partial match


@dataclass
class EvalResult:
    """Precision/recall/F1 for a single label class on a single binary."""

    binary_stem: str
    label_class: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


# ── Pipeline Result (aggregation) ───────────────────────────────────────────


@dataclass
class PipelineResult:
    """Final output of a complete mining run."""

    binary_path: str
    run_id: str
    memory_map: Optional[MemoryMap] = None
    stage2_degraded: bool = False
    stage2_degraded_reason: str = ""
    stage2_degraded_metadata: Dict[str, Any] = field(default_factory=dict)
    source_candidates: List[SourceCandidate] = field(default_factory=list)
    sink_candidates: List[SinkCandidate] = field(default_factory=list)
    evidence_packs: List[EvidencePack] = field(default_factory=list)
    proposals: List[LLMProposal] = field(default_factory=list)
    verified_labels: List[VerifiedLabel] = field(default_factory=list)
    stage_errors: Dict[str, str] = field(default_factory=dict)
    # All MMIO addresses detected by the pipeline: {addr: "load"|"store"|"both"}
    all_mmio_addrs: Dict[int, str] = field(default_factory=dict)
