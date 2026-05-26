import unittest

from core.modules.data_flow_intel import analyze_function_data_flow
from core.modules.xrefs_foundation import XrefRecord


class DataFlowIntelTest(unittest.TestCase):
    def test_register_and_api_argument_tracking(self):
        txt = "\n".join([
            "0x00401000: mov rcx, 0x00405000",
            "0x00401007: mov rdx, 0x40",
            "0x0040100E: call KERNEL32!WriteFile",
        ])
        xrefs = [XrefRecord(src=0x0040100E, dst=None, xref_type="import", src_function=0x00401000, dst_function=None, instruction="call KERNEL32!WriteFile", confidence="medium", api="KERNEL32!WriteFile")]
        out = analyze_function_data_flow(txt, xrefs, {0x00405000: "hello"})
        self.assertTrue(out["register_flow"])
        self.assertTrue(out["api_argument_insights"])
        self.assertEqual(out["api_argument_insights"][0]["api"], "KERNEL32!WriteFile")

    def test_string_flow_tracking(self):
        txt = "\n".join([
            "0x00402000: lea rcx, 0x00406000",
            "0x00402007: call KERNEL32!CreateFileW",
        ])
        xrefs = [XrefRecord(src=0x00402007, dst=None, xref_type="import", src_function=0x00402000, dst_function=None, instruction="call KERNEL32!CreateFileW", confidence="medium", api="KERNEL32!CreateFileW")]
        out = analyze_function_data_flow(txt, xrefs, {0x00406000: "C:/temp/a.bin"})
        self.assertTrue(out["string_flows"])


if __name__ == "__main__":
    unittest.main()
