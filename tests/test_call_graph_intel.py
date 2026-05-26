import unittest

from core.modules.call_graph_intel import build_call_graph_model, analyze_call_graph
from core.modules.function_intel import build_function_profiles
from core.modules.xrefs_foundation import XrefRecord


class CallGraphIntelTest(unittest.TestCase):
    def _profiles_and_xrefs(self):
        disasm = "\n".join([
            "0x00401000: call 0x00402000",
            "0x00401005: call 0x00403000",
            "0x00402000: call 0x00403000",
            "0x00403000: ret",
            "0x00404000: ret",
        ])
        funcs = {
            0x00401000: "entry_point",
            0x00402000: "sub_402000",
            0x00403000: "sub_403000",
            0x00404000: "sub_404000",
        }
        xrefs = [
            XrefRecord(src=0x00401000, dst=0x00402000, xref_type="call", src_function=0x00401000, dst_function=0x00402000, instruction="call 0x00402000", confidence="high"),
            XrefRecord(src=0x00401005, dst=0x00403000, xref_type="call", src_function=0x00401000, dst_function=0x00403000, instruction="call 0x00403000", confidence="high"),
            XrefRecord(src=0x00402000, dst=0x00403000, xref_type="call", src_function=0x00402000, dst_function=0x00403000, instruction="call 0x00403000", confidence="high"),
            XrefRecord(src=0x00402010, dst=None, xref_type="call", src_function=0x00402000, dst_function=None, instruction="call qword ptr [rax]", confidence="low"),
        ]
        profiles = build_function_profiles(
            disasm_text=disasm,
            functions=funcs,
            xrefs=xrefs,
            comments={"0x00402000": "suspicious bridge"},
            labels={},
            bookmarks=[],
        )
        return profiles, xrefs

    def test_call_graph_construction(self):
        profiles, xrefs = self._profiles_and_xrefs()
        g = build_call_graph_model(profiles, xrefs)
        self.assertGreaterEqual(len(g["nodes"]), 4)
        self.assertTrue(any(e["caller"] == "0x00401000" and e["callee"] == "0x00402000" for e in g["edges"]))

    def test_hub_leaf_and_isolated_detection(self):
        profiles, xrefs = self._profiles_and_xrefs()
        g = build_call_graph_model(profiles, xrefs)
        s = analyze_call_graph(g, entry_point=0x00401000)
        self.assertTrue(any(h["address"] == "0x00403000" for h in s["top_hub_functions"]))
        self.assertIn("0x00404000", s["isolated_or_unreferenced_functions"])
        self.assertTrue(any(l["address"] == "0x00403000" for l in s["leaf_functions"]))

    def test_suspicious_chain_detection(self):
        profiles, xrefs = self._profiles_and_xrefs()
        g = build_call_graph_model(profiles, xrefs)
        s = analyze_call_graph(g, entry_point=0x00401000)
        self.assertTrue(s["suspicious_call_chains"])
        self.assertTrue(any(c.get("confidence") in ("low", "medium", "high") for c in s["suspicious_call_chains"]))


if __name__ == "__main__":
    unittest.main()
