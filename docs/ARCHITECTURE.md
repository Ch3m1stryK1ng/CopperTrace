# Architecture

## Static Analysis

```text
ELF
 |
 +-- Ghidra exporter
 |     High P-code, CFG, functions, calls, LOAD/STORE, ValueId/ObjectId
 |
 +-- Source Miner
 |     software-interface summaries, MMIO register profiles, DMA evidence
 |
 +-- Sink Miner
 |     standard primitives, recursive wrappers, enabled body patterns
 |     output: Sink site + vulnerable parameters
 |
 +-- Source Association
 |     local def-use, actual/formal, return, proved memory effects
 |
 +-- shared-object Miner
 |     Source-associated write + cross-context overlapping read
 |
 +-- Channelgraph Builder
 |     writer Function -> shared-object Region -> reader Function
 |
 +-- Unified Graph Analysis
       Call and Channel relations participate in one reverse search;
       backward data-flow analysis follows the selected relations.
```

## Recognition Methods

Source and Sink semantic labels are separate from recognition methods:

```text
deterministic
  exact instruction/callsite evidence and a proved role binding

heuristic
  a generalized body pattern whose evidence level remains attached to
  downstream Alerts
```

Rules must not depend on a CVE identifier, sample identifier, or exact
application-function name. Hardware profiles identify register roles by
address and peripheral metadata; public-CVE profiles are used only after
analysis to measure reproduction.

## Artifact Contracts

The pipeline exchanges JSON artifacts rather than rewriting Decompiled C:

```text
ProgramFacts
  functions, CFG, High P-code, LOAD/STORE/CALL facts

sources.json
  Source site, Source buffer/value, evidence level

sinks.json
  Sink site, semantic label, vulnerable parameters, evidence level

channel_graph.json
  Function/shared-object nodes and Call/Channel relations

chains.json
  per-Sink-parameter backward result and complete evidence path
```

Schemas in `schemas/` define the graph, chain, review, and validation
contracts. Generated firmware artifacts are deliberately kept outside this
code repository.

## Optional Review

Static Alerts are first deduplicated by the A2 filter. The optional review
stage receives each unchanged canonical Alert plus bounded Check evidence and
the relevant Decompiled C. Review output is partitioned into retained,
rejected, and unresolved results; execution or parse failures are never
treated as semantic rejection.
