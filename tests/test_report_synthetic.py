import unittest
import importlib.util

from core.modules.report import render_html


@unittest.skipUnless(importlib.util.find_spec("jinja2") is not None, "jinja2 is required for render_html tests")
class ReportSyntheticRenderTest(unittest.TestCase):
    def test_render_html_minimal_payload_has_core_headers(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-MIN", "examiner": "QA", "analyst_notes": "minimal"},
            "meta": {"path": "minimal.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
        }
        html = render_html(data)
        self.assertIn("Executive Summary", html)
        self.assertIn("File / PE Metadata", html)
        self.assertIn("Sections", html)
        self.assertIn("Imports", html)
        self.assertIn("Exports", html)
        self.assertIn("Resources", html)
        self.assertIn("Risk Findings", html)
        self.assertIn("Packer / Obfuscation", html)
        self.assertIn("Notes", html)
        self.assertIn("Conclusions", html)
        self.assertIn("Recommendations", html)

    def test_render_html_with_minimal_fake_data(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-1", "examiner": "QA", "analyst_notes": "test"},
            "meta": {
                "path": "sample.exe",
                "size": 1234,
                "image_base": "0x400000",
                "entry_point": "0x401000",
                "machine": "0x14c",
                "timestamp": 0,
                "timestamp_iso": "1970-01-01 00:00:00Z",
                "subsystem": 2,
                "dll_characteristics": 0,
            },
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
        }

        html = render_html(data)
        self.assertIn("EREVOS", html)
        self.assertIn("sample.exe", html)
        self.assertNotIn("Triage Analysis 2.0", html)
        self.assertIn("Executive Summary", html)
        self.assertIn("Conclusions", html)
        self.assertIn("Recommendations", html)

    def test_render_html_with_triage_payload(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-2", "examiner": "QA", "analyst_notes": "triage test"},
            "meta": {
                "path": "triage.exe",
                "size": 2222,
                "image_base": "0x400000",
                "entry_point": "0x401050",
                "machine": "0x8664",
                "timestamp": 1,
                "timestamp_iso": "1970-01-01 00:00:01Z",
                "subsystem": 3,
                "dll_characteristics": 0,
            },
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {
                "score": 77,
                "verdict": "high",
                "findings": ["process injection capability suspected"],
                "capability_tags": ["process_injection_suspected"],
                "rule_hits": [{"name": "injection_combo", "severity": "high", "tag": "process_injection_suspected", "message": "combo hit"}],
                "plugins": [{"plugin": "p.test", "error": None, "result": {"ok": True}}],
                "hashes": {"imphash": "abc", "rich_hash": "def", "fuzzy_hash": "ghi"},
                "evidence": [{"rule": "api_combo", "details": "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread"}],
                "stats": {
                    "entropy_heatmap": [{"offset": 0, "size": 512, "entropy": 7.8}],
                    "imports": {"clusters": {"network": ["connect"]}, "api_combinations": ["remote_thread_injection_combo"]},
                    "oep": {"entrypoint_rva": 4096, "entrypoint_va": 4198400, "entrypoint_file_offset": 1024, "entrypoint_section": ".text", "entrypoint_bytes_hex": "90", "oep_disasm_preview": ["0x401050: nop"]},
                    "tls": {"count": 1, "callbacks": ["0x401000"]},
                    "overlay": {"overlay_size": 32, "overlay_ratio": 0.01, "classification": "opaque_blob", "preview_hex": "4d5a"},
                    "header_anomalies": ["abnormal_number_of_sections"],
                    "sections": {"resource_entropy": [{"name": ".rsrc", "entropy": 7.5}]},
                    "artifacts": {"artifacts": [{"offset": 123, "encoding": "ascii", "value": "http://c2"}]},
                },
            },
        }
        html = render_html(data)
        self.assertIn("Triage Analysis 2.0", html)
        self.assertIn("process_injection_suspected", html)
        self.assertIn("VirtualAllocEx+WriteProcessMemory+CreateRemoteThread", html)
        self.assertIn("Severity: High", html)
        self.assertIn("Analyst Interpretation", html)

    def test_render_html_with_function_intel_summary(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-3", "examiner": "QA", "analyst_notes": "fi test"},
            "meta": {"path": "fi.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "function_intelligence_summary": {
                "top_risky_functions": [
                    {
                        "start": "0x00401000",
                        "risk_indicators": ["suspicious_api_usage"],
                        "suspicious_api_usage": ["KERNEL32!VirtualAlloc"],
                        "inbound_xrefs": 5,
                    }
                ],
                "functions_with_suspicious_apis": [{"start": "0x00401000", "apis": ["KERNEL32!VirtualAlloc"]}],
                "functions_with_interesting_strings": [{"start": "0x00401000", "strings": ["http://x"]}],
                "analyst_renamed_functions": [{"address": "0x00401000", "name": "main"}],
                "commented_or_bookmarked_functions": [{"start": "0x00401000", "comments": ["note"], "bookmarked": True}],
            },
        }
        html = render_html(data)
        self.assertIn("Function Intelligence Summary", html)
        self.assertIn("0x00401000", html)
        self.assertIn("KERNEL32!VirtualAlloc", html)

    def test_render_html_with_wrapped_function_intel_summary(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-4", "examiner": "QA", "analyst_notes": "wrapper test"},
            "meta": {"path": "fi2.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "analyst_artifacts": {
                "function_intelligence_summary": [{
                    "top_risky_functions": [{"start": "0x00402000", "risk_indicators": [], "suspicious_api_usage": [], "inbound_xrefs": 1}],
                    "functions_with_suspicious_apis": [],
                    "functions_with_interesting_strings": [],
                    "analyst_renamed_functions": [],
                    "commented_or_bookmarked_functions": [],
                }]
            },
        }
        html = render_html(data)
        self.assertIn("Function Intelligence Summary", html)
        self.assertIn("0x00402000", html)

    def test_render_html_with_behavioral_summaries(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-5", "examiner": "QA", "analyst_notes": "behavior test"},
            "meta": {"path": "fi3.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "function_intelligence_summary": {
                "top_risky_functions": [{"start": "0x00403000"}],
                "functions_with_suspicious_apis": [],
                "functions_with_interesting_strings": [],
                "analyst_renamed_functions": [],
                "commented_or_bookmarked_functions": [],
            },
            "behavior_summaries": {
                "0x00403000": {
                    "function_address": "0x00403000",
                    "short_behavior_summary": "Function likely performs sensitive API-mediated operations (static heuristic).",
                    "evidence_bullets": ["Suspicious API references: KERNEL32!VirtualAlloc."],
                    "confidence": "high",
                    "possible_capability_tags": ["suspicious_api_usage"],
                    "caveats": ["Heuristic behavioral summary derived from static evidence only."],
                }
            },
        }
        html = render_html(data)
        self.assertIn("Behavioral Function Summaries", html)
        self.assertIn("0x00403000", html)
        self.assertIn("Suspicious API references", html)

    def test_render_html_with_call_graph_intelligence(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-6", "examiner": "QA", "analyst_notes": "cg test"},
            "meta": {"path": "cg.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "call_graph_summary": {
                "entry_reachable_functions": ["0x00401000", "0x00402000"],
                "top_hub_functions": [{"address": "0x00402000", "inbound_degree": 3, "outbound_degree": 4, "suspicious": True}],
                "suspicious_call_chains": [{"chain": ["0x00401000", "0x00402000"], "reason": "suspicious endpoint in call relation", "confidence": "medium"}],
                "suspicious_api_bridge_functions": [{"address": "0x00402000", "inbound_degree": 3, "suspicious_apis": ["KERNEL32!VirtualAlloc"]}],
                "isolated_or_unreferenced_functions": ["0x00404000"],
                "heuristic_note": "static heuristic only",
            },
        }
        html = render_html(data)
        self.assertIn("Call Graph Intelligence", html)
        self.assertIn("0x00402000", html)
        self.assertIn("0x00404000", html)

    def test_render_html_with_cfg_intelligence(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-7", "examiner": "QA", "analyst_notes": "cfg test"},
            "meta": {"path": "cfg.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "cfg_intel_summary": {
                "0x00401000": {
                    "analysis": {
                        "basic_block_count": 5,
                        "branch_count": 7,
                        "branch_density": 1.4,
                        "unresolved_edge_count": 1,
                        "abnormal_high_branch_density": True,
                        "loop_back_edge_hints": [{"src": "0x00401020", "dst": "0x00401000"}],
                        "possible_opaque_predicate_hints": [{"block": "0x00401030", "reason": "possible"}],
                        "unreachable_block_hints": ["0x00401080"],
                    }
                }
            },
        }
        html = render_html(data)
        self.assertIn("CFG Intelligence", html)
        self.assertIn("0x00401000", html)
        self.assertIn("Possible opaque predicates", html)

    def test_render_html_with_naming_intelligence(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-8", "examiner": "QA", "analyst_notes": "name test"},
            "meta": {"path": "name.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "analyst_artifacts": {"renamed_functions": {"0x00401000": "analyst_name"}},
            "naming_suggestions": {
                "0x00402000": {
                    "address": "0x00402000",
                    "suggested_name": "possible_network_init_00402000",
                    "confidence": "high",
                    "evidence_bullets": ["Network-related API references observed."],
                    "caveats": ["Heuristic naming only."],
                }
            },
        }
        html = render_html(data)
        self.assertIn("Symbol &amp; Naming Intelligence", html)
        self.assertIn("possible_network_init_00402000", html)

    def test_render_html_with_data_flow_insights(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-9", "examiner": "QA", "analyst_notes": "dfi test"},
            "meta": {"path": "dfi.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "data_flow_insights": {
                "0x00401000": {
                    "high_confidence_findings": [
                        {"type": "api_argument_insight", "api": "KERNEL32!WriteFile", "call_site": "0x00401020", "evidence": "Register state observed", "estimated": True}
                    ]
                }
            },
        }
        html = render_html(data)
        self.assertIn("Data Flow Insights", html)
        self.assertIn("KERNEL32!WriteFile", html)

    def test_render_html_with_api_semantics_intelligence(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-10", "examiner": "QA", "analyst_notes": "api semantics test"},
            "meta": {"path": "api.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "api_semantics_insights": {
                "0x00401000": {
                    "high_value_calls": [
                        {
                            "api": "KERNEL32!VirtualAlloc",
                            "call_site": "0x00401020",
                            "capability_tags": ["memory_allocation", "executable_memory"],
                            "interpreted_arguments": ["flProtect=0x40 (estimated) -> suggests executable memory protection indicator"],
                            "evidence": "API observed with estimated argument state",
                            "confidence": "high",
                            "estimated": True,
                        }
                    ]
                }
            },
        }
        html = render_html(data)
        self.assertIn("API Semantics Intelligence", html)
        self.assertIn("VirtualAlloc", html)

    def test_render_html_with_behavior_pattern_detection(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-11", "examiner": "QA", "analyst_notes": "behavior pattern test"},
            "meta": {"path": "behaviors.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "behavior_patterns": {
                "high_confidence_patterns": [
                    {
                        "pattern": "process injection",
                        "confidence": "high",
                        "scope": "per-function",
                        "involved_functions": ["0x00401000"],
                        "evidence_chain": [
                            "KERNEL32!OpenProcess @ 0x00401010 | args=['dwDesiredAccess=0x1F0FFF (estimated)']",
                            "KERNEL32!WriteProcessMemory @ 0x00401020 | args=['lpBuffer=payload (estimated)']",
                            "KERNEL32!CreateRemoteThread @ 0x00401030 | args=[]",
                        ],
                        "caveats": ["Static sequence suggests injection behavior candidate."],
                    }
                ]
            },
        }
        html = render_html(data)
        self.assertIn("Behavior Pattern Detection", html)
        self.assertIn("process injection", html)

    def test_render_html_with_threat_narrative(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-12", "examiner": "QA", "analyst_notes": "threat narrative test"},
            "meta": {"path": "narrative.exe", "machine": "0x14c"},
            "sections": [],
            "imports": {},
            "exports": [],
            "resources": {},
            "risk": [],
            "packer": {},
            "strings": [],
            "notes": [],
            "triage": {},
            "threat_narrative": {
                "threat_overview": {
                    "summary": "Static evidence suggests possible process injection behavior candidate.",
                    "evidence": ["process injection: KERNEL32!OpenProcess @ 0x00401010"],
                },
                "capability_summary": [{"capability": "process injection", "confidence": "high"}],
                "execution_flow_summary": ["opens target process → writes payload bytes → creates remote thread (candidate chain)"],
                "key_functions": [{"function": "0x00401000", "role": "pattern-linked function", "why_it_matters": "Appears in evidence chain."}],
                "indicators_of_compromise": {"urls": ["http://example.test"], "ips": [], "file_paths": ["C:/temp/drop.bin"], "mutexes": [], "relevant_api_usage": ["KERNEL32!WriteProcessMemory @ 0x00401020"]},
                "risk_assessment": {"level": "critical", "reason": "High-confidence execution-manipulation patterns indicate potentially severe malicious capability candidates."},
                "caveats": ["Static analysis only."],
            },
        }
        html = render_html(data)
        self.assertIn("Threat Narrative", html)
        self.assertIn("Execution Flow Summary", html)

    def test_render_html_maximal_payload_has_all_major_sections(self):
        data = {
            "schema_version": "erevos.report.v2",
            "case": {"case_id": "CASE-MAX", "examiner": "QA", "analyst_notes": "maximal"},
            "meta": {
                "path": "maximal.exe",
                "size": 1111,
                "image_base": "0x400000",
                "entry_point": "0x401000",
                "machine": "0x14c",
                "timestamp": 0,
                "timestamp_iso": "1970-01-01 00:00:00Z",
                "subsystem": 2,
                "dll_characteristics": 0,
            },
            "sections": [{"name": ".text", "va": "0x401000", "raw_size": 512, "virtual_size": 1024, "characteristics": 0x60000020, "executable": True, "entropy": 6.8}],
            "imports": {"KERNEL32.dll": ["CreateFileW"]},
            "exports": [{"va": "0x401000", "name": "ExportedEntry"}],
            "resources": {"manifest": ["<assembly/>"], "version_info": {"FileVersion": "1.0.0.0"}},
            "risk": [{"va": "0x401000", "name": "sub_401000", "score": 80, "reason": "suspicious api", "reasons": ["api"], "hints": []}],
            "packer": {"score": 10, "reasons": [], "hints": []},
            "strings": [{"va": "0x402000", "rva": "0x2000", "file_off": "0x600", "encoding": "ascii", "text": "http://example.test"}],
            "notes": ["note 1"],
            "triage": {
                "score": 72,
                "verdict": "high",
                "findings": ["injection candidate"],
                "capability_tags": ["process_injection_suspected"],
                "rule_hits": [{"name": "combo"}],
                "plugins": [],
                "hashes": {"imphash": "abc", "rich_hash": "def", "fuzzy_hash": "ghi"},
                "evidence": [{"rule": "api_combo", "details": "VirtualAllocEx+WriteProcessMemory+CreateRemoteThread"}],
                "stats": {"entropy_heatmap": [], "imports": {"clusters": {}, "api_combinations": []}, "oep": {"oep_disasm_preview": []}, "tls": {"count": 0}, "overlay": {"overlay_size": 0}, "header_anomalies": [], "sections": {"resource_entropy": []}, "artifacts": {"artifacts": []}},
            },
            "xrefs_summary": {"top_called_functions": ["0x401000"]},
            "function_intelligence_summary": {"top_risky_functions": [{"start": "0x00401000", "risk_indicators": [], "suspicious_api_usage": [], "inbound_xrefs": 1}], "functions_with_suspicious_apis": [], "functions_with_interesting_strings": [], "analyst_renamed_functions": [], "commented_or_bookmarked_functions": []},
            "behavior_summaries": {"0x00401000": {"function_address": "0x00401000", "short_behavior_summary": "heuristic summary", "evidence_bullets": ["e1"], "confidence": "low", "possible_capability_tags": [], "caveats": ["heuristic"]}},
            "call_graph_summary": {"entry_reachable_functions": ["0x00401000"], "top_hub_functions": [{"address": "0x00401000", "inbound_degree": 1, "outbound_degree": 1, "suspicious": False}], "suspicious_call_chains": [], "suspicious_api_bridge_functions": [], "isolated_or_unreferenced_functions": [], "heuristic_note": "heuristic"},
            "cfg_intel_summary": {"0x00401000": {"analysis": {"basic_block_count": 2, "branch_count": 1, "branch_density": 0.5, "unresolved_edge_count": 0, "abnormal_high_branch_density": False}}},
            "naming_suggestions": {"0x00401000": {"address": "0x00401000", "suggested_name": "possible_main_00401000", "confidence": "high", "evidence_bullets": ["e"], "caveats": []}},
            "data_flow_insights": {"0x00401000": {"high_confidence_findings": [{"type": "api_argument_insight", "api": "KERNEL32!WriteFile", "call_site": "0x00401020", "evidence": "reg state", "estimated": True}]}},
            "api_semantics_insights": {"0x00401000": {"high_value_calls": [{"api": "KERNEL32!VirtualAlloc", "call_site": "0x00401030", "capability_tags": ["memory_allocation"], "interpreted_arguments": [], "evidence": "x", "confidence": "high", "estimated": True}]}},
            "behavior_patterns": {"high_confidence_patterns": [{"pattern": "process injection", "confidence": "high", "scope": "per-function", "involved_functions": ["0x00401000"], "evidence_chain": ["OpenProcess @ ..."], "caveats": ["heuristic"]}]},
            "threat_narrative": {"threat_overview": {"summary": "Static evidence suggests possible process injection behavior candidate.", "evidence": ["process injection: OpenProcess"]}, "capability_summary": [{"capability": "process injection", "confidence": "high"}], "execution_flow_summary": ["opens process -> writes payload -> creates thread"], "key_functions": [{"function": "0x00401000", "role": "pattern-linked function", "why_it_matters": "important"}], "indicators_of_compromise": {"urls": ["http://example.test"], "ips": [], "file_paths": [], "mutexes": [], "relevant_api_usage": []}, "risk_assessment": {"level": "high", "reason": "patterns"}, "caveats": ["static only"]},
            "analyst_artifacts": {"renamed_functions": {"0x00401000": "main"}, "comments": {"0x00401000": "note"}, "labels": {"0x00401000": "entry"}, "bookmarks": ["0x00401000"]},
        }
        html = render_html(data)
        for hdr in [
            "Threat Narrative",
            "Executive Summary",
            "Triage Analysis 2.0",
            "XREF Summary",
            "Function Intelligence Summary",
            "Behavioral Function Summaries",
            "Call Graph Intelligence",
            "CFG Intelligence",
            "Symbol &amp; Naming Intelligence",
            "Data Flow Insights",
            "API Semantics Intelligence",
            "Behavior Pattern Detection",
            "Analyst Workspace Artifacts",
            "Conclusions",
            "Recommendations",
            "Notes",
        ]:
            self.assertIn(hdr, html)


if __name__ == "__main__":
    unittest.main()
