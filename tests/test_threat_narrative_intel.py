import unittest

from core.modules.threat_narrative_intel import build_threat_narrative


class ThreatNarrativeIntelTest(unittest.TestCase):
    def test_structured_narrative_from_patterns(self):
        narrative = build_threat_narrative(
            behavior_patterns={
                "patterns": [
                    {
                        "pattern": "process injection",
                        "confidence": "high",
                        "involved_functions": ["0x00401000"],
                        "evidence_chain": [
                            "KERNEL32!OpenProcess @ 0x00401010 | args=[]",
                            "KERNEL32!WriteProcessMemory @ 0x00401020 | args=[]",
                            "KERNEL32!CreateRemoteThread @ 0x00401030 | args=[]",
                        ],
                    }
                ],
                "high_confidence_patterns": [
                    {
                        "pattern": "process injection",
                        "confidence": "high",
                        "involved_functions": ["0x00401000"],
                        "evidence_chain": ["KERNEL32!OpenProcess @ 0x00401010 | args=[]"],
                    }
                ],
            },
            api_semantics={
                "0x00401000": {
                    "high_value_calls": [
                        {
                            "api": "KERNEL32!WriteProcessMemory",
                            "call_site": "0x00401020",
                            "capability_tags": ["process_injection_candidate"],
                            "confidence": "high",
                        }
                    ]
                }
            },
            data_flow_insights={"0x00401000": {"high_confidence_findings": [{"type": "api_argument_insight"}]}} ,
            function_intelligence={
                "top_risky_functions": [
                    {
                        "start": "0x00401000",
                        "risk_indicators": ["remote thread creation"],
                        "suspicious_api_usage": ["CreateRemoteThread"],
                    }
                ]
            },
            call_graph_intelligence={"top_hub_functions": [{"address": "0x00401000", "inbound_degree": 2, "outbound_degree": 3}]},
            cfg_intelligence={"0x00401000": {"analysis": {"abnormal_high_branch_density": True}}},
            hashes_and_metadata={"path": "sample.exe", "entry_point": "0x00401000", "hashes": {"sha256": "abc"}},
            extracted_strings=["http://example.test/payload", "C:/temp/drop.bin", "mutex_agent_01"],
        )
        self.assertIn("threat_overview", narrative)
        self.assertIn("suggests", narrative["threat_overview"]["summary"].lower())
        self.assertEqual("critical", narrative["risk_assessment"]["level"])
        self.assertTrue(narrative["indicators_of_compromise"]["urls"])


if __name__ == "__main__":
    unittest.main()
