# Erevos Audit + Architecture Proposal for **PE Static Analysis Platform 2.0**

## 1) Repository Audit (Current State)

### 1.1 High-level findings

Erevos already has useful building blocks (GUI, basic PE parsing, disassembly, strings, resources, risk tab, packer heuristics). However, the current implementation is **monolithic and tightly coupled**, and many analysis paths are **heuristic-only and non-forensic-grade**.

### 1.2 Concrete weaknesses observed in code

#### Architecture / Maintainability
- `core/app.py` combines UI, orchestration, module integration, and analysis actions in one large class/module, making extension/testing difficult.
- Optional module imports are scattered and silently downgraded, reducing observability when capabilities fail.
- Multiple duplicated imports and style inconsistencies indicate low cohesion.

#### Parsing / PE assumptions
- `core/pedisasm.py` parses PE directly and mixes concerns (parsing + disassembly + string extraction + module calls).
- Entry/function detection is simplistic (`55 8B EC` prologue scan), architecture-biased, and misses modern optimized binaries.
- Disassembly methods do not include robust range/exception boundaries for malformed files.

#### Analysis Depth
- Risk model in `core/modules/risk.py` is useful but shallow and largely API-name based.
- Packer detection in `core/modules/packer.py` has good heuristics but no confidence calibration and limited packer family discrimination.
- No ATT&CK mapping model, no explicit capability graph, no behavior-family evidence model.

#### Forensic / Evidence Quality
- No canonical evidence object linking each finding to exact byte/VA/RVA/source component.
- No chain-of-analysis append-only model for audit traceability.
- No multi-format forensic report model with section-level evidence references.

#### Signature + Threat Intelligence
- No YARA integration.
- No capability signatures (capa-style rule layer).
- No family-tagging abstraction and no scoring explanation schema.

#### Cryptographic / Certificate coverage
- Missing consolidated hashing layer (MD5/SHA1/SHA256/SHA512 in one standard path).
- Authenticode analysis is not yet a first-class engine module.

#### .NET support
- No dedicated CLR metadata parser/analyzer pipeline despite roadmap goals.

#### Testing / Reliability
- No formal test suite around malformed PE edge cases.
- Limited contract-level interfaces for modular analyzers.

---

## 2) PE Static Analysis 2.0 Target Architecture

## 2.1 Design principles
- **Explainable-by-default**: every detection must contain machine-readable evidence.
- **Modular pipeline**: parser/analyzer/heuristic/reporting are separate stages.
- **Forensic-safe**: immutable facts + append-only analysis log.
- **Graceful degradation**: unavailable modules are reported explicitly, not silently ignored.
- **Extensible**: plugin architecture for custom heuristics/signatures.

## 2.2 Proposed package topology

```text
core/v2/
  core/          # Pipeline, orchestration, error boundaries
  parsers/       # PE, directories, certificate, CLR metadata parsers
  analyzers/     # imports, exports, sections, resources, strings, anti-analysis, persistence
  heuristics/    # packer, capability scoring, ATT&CK tagging, anomaly scoring
  signatures/    # YARA adapter + rule bundles + capa-style signatures
  disasm/        # Capstone backend + instruction feature extraction
  reporting/     # JSON/HTML/PDF formatters, evidence indexing
  plugins/       # External analyzer plugin hooks
  utils/         # hashing, io-safe utilities, normalization helpers
  models/        # Typed contracts: Evidence, Finding, Context
```

## 2.3 Analysis flow (proposed)
1. **Ingest**: open PE safely, capture file metadata + hashes.
2. **Parse**: DOS/NT/Optional/Section/DataDirectory extraction with strict validation.
3. **Feature Extraction**: imports/exports/resources/strings/disassembly opcode stats.
4. **Behavior Heuristics**: ATT&CK tagging, anti-analysis markers, persistence/injection/network hints.
5. **Capability Layer**: rule-based capability labels with supporting evidence.
6. **Scoring**: explainable weighted score with reason components.
7. **Reporting**: JSON/HTML(/PDF optional) with assignment-analysis-findings-conclusions-recommendations sections.
8. **Audit Log Export**: full chain of analysis events with UTC timestamps.

---

## 3) Concrete Initial Refactor Implemented in this change set

To start the 2.0 migration without breaking the current UI, this patch introduces a foundational v2 scaffold:

1. **Typed evidence/finding/context contracts** (`core/v2/models/contracts.py`)
   - Adds first-class evidence objects (source, field, value, offset/rva/va).
   - Adds finding model with severity/confidence/ATT&CK tags.
   - Adds append-only analysis log events.

2. **Pipeline orchestrator** (`core/v2/core/pipeline.py`)
   - Introduces stage-based execution with stage start/end logging.
   - Provides stable extension point for parser/analyzer/signature modules.

3. **Forensic hashing utility** (`core/v2/utils/hashing.py`)
   - Streaming MD5/SHA1/SHA256/SHA512 computation for large-file safety.

4. **Package skeleton for module separation** (`core/v2/*/__init__.py`)
   - Establishes clear boundaries for future analyzers and parsers.

---

## 4) Next-phase implementation plan (priority order)

### Phase A — Parsing hardening
- Implement strict PE parser wrappers for all 16 data directories.
- Add overlay, alignment, section permission anomaly logic as reusable analyzers.
- Add malformed input tests + fuzz corpus.

### Phase B — Advanced analysis depth
- Imports intelligence engine (API clusters, suspicious combos, ATT&CK tactics).
- Entry point profiler (entropy window + byte-pattern + disasm preview).
- Anti-analysis detector (PEB access, timing ops, debugger probes, TLS callbacks).
- Persistence/injection heuristic suite.

### Phase C — Signatures + capabilities
- YARA integration with ruleset management.
- Capability rule DSL (capa-inspired) with evidence binding.
- Family heuristic tags with confidence/rationale.

### Phase D — Forensic reporting + UI 2.0
- Structured report generators (JSON/HTML/PDF).
- GUI data providers decoupled from parsing logic.
- Threaded analysis worker + progress/event stream + searchable tables.

---

## 5) Why this architecture matters for malware triage
- Reduces false confidence by forcing **evidence-linked findings**.
- Enables repeatable triage through deterministic pipeline stages.
- Improves forensic defensibility with append-only logs and full hash integrity.
- Supports rapid expansion (YARA, capabilities, .NET, certificate validation) without rewriting core UI.
