# PE Static Analysis 2.0 — Top 10 Upgrades (Executed Priority Order)

## Repository map (quick)
- `core/pedisasm.py`: core disassembly wrapper.
- `core/modules/`: analysis modules (`risk`, `packer`, `resources`, `xrefs`, `report`, `triage`).
- `core/app.py`: PyQt UI and workflow orchestration.
- `docs/`: architecture and project guidance.

## Top 10 high-value upgrades

1. **Hostile-input PE parsing guardrails** (implemented)
2. **Forensic hash baseline + imphash in triage output** (implemented)
3. **Full data-directory visibility (all 16 dirs)** (implemented)
4. **Section anomaly model (entropy + suspicious names + RWX + alignment)** (implemented)
5. **Entrypoint forensic profile (RVA/VA/offset/bytes/section)** (implemented)
6. **Import intelligence with capability buckets + high-risk API combos** (implemented)
7. **Suspicious string extraction with offsets + high-value categories** (implemented)
8. **Static anti-analysis byte-pattern hints** (implemented)
9. **Certificate table and .NET CLR detection** (implemented)
10. **Explainable weighted scoring tied to explicit evidence** (implemented)

## Why this order
The ordering prioritizes correctness/safety first (parser hardening, hash baseline), then structural PE visibility (directories/sections/entrypoint), then malware behavior signals (imports/strings/anti-analysis), and finally confidence output (scoring + verdict).
