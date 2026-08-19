# CopperTrace

CopperTrace is a research prototype for statically detecting taint-style
vulnerabilities in monolithic firmware. It starts from vulnerable parameters
at memory-safety Sinks, follows data flow backward, and augments the ordinary
Callgraph with a Channelgraph for Cross-Context Communication through
shared-objects.

```text
Firmware ELF
    |
    v
Ghidra High P-code + Decompiled C
    |
    +--> Source Miner
    +--> Sink Miner + vulnerable parameters
    |
    v
Source Association --> shared-object Miner --> Channelgraph
    |
    v
Unified graph (Call + Channel relations)
    |
    v
reverse BFS + backward data-flow analysis
    |
    v
Static Alerts --> A2 deduplication --> optional Check/LLM review
```

This repository contains the reviewable implementation, rule registries,
schemas, and tests. Firmware binaries, public-CVE datasets, decompiler caches,
analysis outputs, and model credentials are intentionally excluded. They can
be distributed as a separate artifact.

## Repository Layout

- `scripts/`: miners, graph construction, data-flow analysis, filtering,
  review, evaluation, and execution-validation adapters
- `registries/`: Source/Sink rules and hardware register profiles
- `schemas/`: stable JSON artifact contracts
- `sourceagent/`: the small set of original CopperTrace compatibility modules
  used by the current pipeline
- `tests/`: unit and regression tests that do not require the private datasets
- `examples/`: dataset-free manifest examples

See [Architecture](docs/ARCHITECTURE.md) for the main stages and artifacts.

## Requirements

- Python 3.10 or newer
- Ghidra and a compatible JDK for whole-image High P-code export
- An ELF-form monolithic firmware image
- Optional: an LLM endpoint for the post-analysis review stage

Install the local package and development dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev,ghidra]'
```

Configure local tool paths:

```bash
cp .env.example .env
export GHIDRA_INSTALL_DIR=/path/to/ghidra
export JAVA_HOME=/path/to/jdk
```

## Running the Static Pipeline

Create a manifest from `examples/manifest.json`, then run:

```bash
python3 scripts/run_mini_pipeline.py \
  --manifest /path/to/manifest.json \
  --source-profiles examples/empty_source_profiles.json \
  --out artifacts/run-001
```

The public-CVE answer profiles used by the paper are evaluation-only inputs;
they are not consumed by Source/Sink mining, graph construction, BFS, or
data-flow analysis.

Core per-firmware outputs are:

```text
sources.json        Source sites and Source buffers/values
sinks.json          Sink startpoints and vulnerable parameters
channel_graph.json  Function, shared-object, Call, and Channel relations
chains.json         backward data-flow results for each vulnerable parameter
```

Run the dataset-independent tests with:

```bash
pytest
ruff check scripts sourceagent tests
```

## Scope

The current default pipeline targets out-of-bounds memory-buffer operations
and externally controlled format strings. Pure parser-load/pointer-walk
out-of-bounds access, lifetime errors, and general protocol-state flaws are not
claimed as supported Sink classes.

## License

MIT. See [LICENSE](LICENSE).
