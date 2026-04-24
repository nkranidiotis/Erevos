import tempfile
import unittest
from pathlib import Path

from core.modules.session_state import SessionState


class SessionPersistenceTest(unittest.TestCase):
    def test_roundtrip(self):
        st = SessionState(
            renamed_functions={"0x401000": "entry_main"},
            original_functions={"0x401000": "sub_401000"},
            comments={"0x401000": "suspicious api usage"},
            labels={"0x401020": "decrypt_loop"},
            bookmarks=["0x401000", "0x401020"],
            last_opened_file="sample.exe",
            triage_metadata={"score": 75},
            report_metadata={"last_html": "r.html"},
            function_intel_summary={"top_risky_functions": [{"start": "0x401000"}]},
            behavior_summaries={"0x401000": {"short_behavior_summary": "test", "evidence_bullets": ["x"], "confidence": "low", "possible_capability_tags": [], "caveats": ["heuristic"]}},
            call_graph_summary={"top_hub_functions": [{"address": "0x401000"}]},
            cfg_intel_summary={"0x401000": {"analysis": {"basic_block_count": 3}}},
            naming_suggestions={"0x401000": {"suggested_name": "possible_network_init_00401000", "confidence": "high"}},
            applied_suggested_names={"0x401000": "possible_network_init_00401000"},
            data_flow_insights={"0x401000": {"api_argument_insights": [{"api": "KERNEL32!WriteFile"}]}},
            api_semantics_insights={"0x401000": {"high_value_calls": [{"api": "KERNEL32!WriteFile", "call_site": "0x401020"}]}},
            behavior_patterns={"patterns": [{"pattern": "file dropper", "confidence": "medium"}]},
            threat_narrative={"risk_assessment": {"level": "medium"}},
        )
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sample.exe.erevos"
            st.save(p)
            rd = SessionState.load(p)
            self.assertEqual(rd.renamed_functions["0x401000"], "entry_main")
            self.assertIn("0x401020", rd.bookmarks)
            self.assertEqual(rd.triage_metadata.get("score"), 75)
            self.assertEqual(rd.function_intel_summary["top_risky_functions"][0]["start"], "0x401000")
            self.assertEqual(rd.behavior_summaries["0x401000"]["confidence"], "low")
            self.assertEqual(rd.call_graph_summary["top_hub_functions"][0]["address"], "0x401000")
            self.assertEqual(rd.cfg_intel_summary["0x401000"]["analysis"]["basic_block_count"], 3)
            self.assertEqual(rd.naming_suggestions["0x401000"]["confidence"], "high")
            self.assertEqual(rd.applied_suggested_names["0x401000"], "possible_network_init_00401000")
            self.assertEqual(rd.data_flow_insights["0x401000"]["api_argument_insights"][0]["api"], "KERNEL32!WriteFile")
            self.assertEqual(rd.api_semantics_insights["0x401000"]["high_value_calls"][0]["api"], "KERNEL32!WriteFile")
            self.assertEqual(rd.behavior_patterns["patterns"][0]["pattern"], "file dropper")
            self.assertEqual(rd.threat_narrative["risk_assessment"]["level"], "medium")

    def test_backward_compatible_tuple_wrapped_function_intel(self):
        payload = {
            "renamed_functions": {},
            "original_functions": {},
            "comments": {},
            "labels": {},
            "bookmarks": [],
            "function_intel_summary": ({
                "top_risky_functions": [{"start": "0x401111"}],
                "functions_with_suspicious_apis": [],
                "functions_with_interesting_strings": [],
                "analyst_renamed_functions": [],
                "commented_or_bookmarked_functions": [],
            },),
            "behavior_summaries": ([{"0x401111": {"confidence": "low", "evidence_bullets": ["x"]}}]),
            "call_graph_summary": ([{"top_hub_functions": [{"address": "0x401111"}]}]),
            "cfg_intel_summary": ([{"0x401111": {"analysis": {"basic_block_count": 2}}}]),
            "naming_suggestions": ([{"0x401111": {"suggested_name": "possible_x_401111", "confidence": "low"}}]),
            "applied_suggested_names": {"0x401111": "possible_x_401111"},
            "data_flow_insights": {"0x401111": {"api_argument_insights": [{"api": "KERNEL32!CreateFileW"}]}},
            "api_semantics_insights": {"0x401111": {"high_value_calls": [{"api": "KERNEL32!CreateFileW"}]}},
            "behavior_patterns": {"patterns": [{"pattern": "file dropper", "confidence": "low"}]},
            "threat_narrative": ({"risk_assessment": {"level": "low"}},),
        }
        st = SessionState.from_dict(payload)
        self.assertIsInstance(st.function_intel_summary, dict)
        self.assertEqual(st.function_intel_summary["top_risky_functions"][0]["start"], "0x401111")
        self.assertIsInstance(st.behavior_summaries, dict)
        self.assertIsInstance(st.call_graph_summary, dict)
        self.assertIsInstance(st.cfg_intel_summary, dict)
        self.assertIsInstance(st.naming_suggestions, dict)
        self.assertEqual(st.applied_suggested_names["0x401111"], "possible_x_401111")
        self.assertEqual(st.data_flow_insights["0x401111"]["api_argument_insights"][0]["api"], "KERNEL32!CreateFileW")
        self.assertEqual(st.api_semantics_insights["0x401111"]["high_value_calls"][0]["api"], "KERNEL32!CreateFileW")
        self.assertEqual(st.behavior_patterns["patterns"][0]["pattern"], "file dropper")
        self.assertEqual(st.threat_narrative["risk_assessment"]["level"], "low")


if __name__ == "__main__":
    unittest.main()
