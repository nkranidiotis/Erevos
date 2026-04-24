import unittest

from core.modules.function_intel import build_function_profiles
from core.modules.naming_intel import generate_all_name_suggestions, select_high_confidence_applications
from core.modules.xrefs_foundation import XrefRecord


class NamingIntelTest(unittest.TestCase):
    def test_api_based_suggested_name(self):
        disasm = "0x00401000: call KERNEL32!RegSetValueExA\n0x00401005: ret"
        profiles = build_function_profiles(
            disasm_text=disasm,
            functions={0x00401000: "sub_401000"},
            xrefs=[XrefRecord(src=0x00401000, dst=None, xref_type="import", src_function=0x00401000, dst_function=None, instruction="call KERNEL32!RegSetValueExA", confidence="medium", api="KERNEL32!RegSetValueExA")],
            comments={},
            labels={},
            bookmarks=[],
        )
        s = generate_all_name_suggestions(profiles)
        self.assertIn("possible_", s["0x00401000"]["suggested_name"])

    def test_string_based_suggested_name(self):
        disasm = "0x00402000: lea ecx, 0x00405000\n0x00402005: ret"
        profiles = build_function_profiles(
            disasm_text=disasm,
            functions={0x00402000: "sub_402000"},
            xrefs=[XrefRecord(src=0x00402000, dst=0x00405000, xref_type="string", src_function=0x00402000, dst_function=None, instruction="lea ecx, 0x00405000", confidence="medium", string_value="decode_key")],
            comments={},
            labels={},
            bookmarks=[],
        )
        s = generate_all_name_suggestions(profiles)
        self.assertIn("candidate", s["0x00402000"]["suggested_name"])

    def test_behavior_based_suggested_name(self):
        disasm = "0x00403000: ret"
        profiles = build_function_profiles(disasm, {0x00403000: "sub_403000"}, [], {}, {}, [])
        behavior = {"0x00403000": {"short_behavior_summary": "Function appears to process notable string data (static heuristic)."}}
        s = generate_all_name_suggestions(profiles, behavior_summaries=behavior)
        self.assertIn("string", s["0x00403000"]["suggested_name"])

    def test_no_overwrite_analyst_names(self):
        suggestions = {
            "0x00404000": {"suggested_name": "possible_network_init_00404000", "confidence": "high"},
            "0x00405000": {"suggested_name": "possible_registry_persistence_00405000", "confidence": "high"},
        }
        analyst = {"0x00404000": "analyst_custom_name"}
        out = select_high_confidence_applications(suggestions, analyst_renamed=analyst, allow_overwrite=False)
        self.assertNotIn("0x00404000", out)
        self.assertIn("0x00405000", out)


if __name__ == "__main__":
    unittest.main()
