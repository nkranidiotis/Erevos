import unittest

from core.modules.function_intel import (
    build_function_profiles,
    summarize_function_intelligence,
    generate_function_behavior_summary,
    generate_all_behavior_summaries,
)
from core.modules.xrefs_foundation import XrefRecord


class FunctionIntelTest(unittest.TestCase):
    def setUp(self):
        self.disasm = "\n".join([
            "0x00401000: push ebp",
            "0x00401001: mov ebp, esp",
            "0x00401003: sub esp, 0x20",
            "0x00401006: mov eax, [ebp+8]",
            "0x00401009: mov [ebp-0x4], eax",
            "0x0040100C: call KERNEL32!CreateFileW",
            "0x00401011: lea ecx, 0x00405000",
            "0x00401016: ret",
            "0x00401100: push ebp",
            "0x00401101: mov ebp, esp",
            "0x00401103: ret",
        ])
        self.functions = {0x00401000: "sub_401000", 0x00401100: "sub_401100"}
        self.xrefs = [
            XrefRecord(src=0x00400FF0, dst=0x00401000, xref_type="call", instruction="call 0x00401000", src_function=0x00400F00, dst_function=0x00401000, confidence="high"),
            XrefRecord(src=0x0040100C, dst=None, xref_type="import", instruction="call KERNEL32!CreateFileW", src_function=0x00401000, dst_function=None, confidence="medium", api="KERNEL32!CreateFileW"),
            XrefRecord(src=0x00401011, dst=0x00405000, xref_type="string", instruction="lea ecx, 0x00405000", src_function=0x00401000, dst_function=None, confidence="medium", string_value="http://mal.example/c2"),
        ]

    def test_profile_creation_stack_and_linkage(self):
        profiles = build_function_profiles(
            disasm_text=self.disasm,
            functions=self.functions,
            xrefs=self.xrefs,
            comments={"0x00401000": "entry-like"},
            labels={"0x00401000": "main"},
            bookmarks=["0x00401000"],
        )
        p = profiles[0x00401000]
        self.assertGreaterEqual(p.instruction_count, 1)
        self.assertEqual(p.prologue_pattern, "frame_pointer_push+set_fp")
        self.assertEqual(p.epilogue_pattern, "ret")
        self.assertEqual(p.stack_frame_size_estimate, 0x20)
        self.assertIn("-0x4", p.local_offsets_estimate)
        self.assertIn("8", p.argument_offsets_estimate)
        self.assertIn("KERNEL32!CreateFileW", p.referenced_apis)
        self.assertIn("http://mal.example/c2", p.referenced_strings)
        self.assertIn("entry-like", p.comments)
        self.assertTrue(p.bookmarks)

    def test_suspicious_api_and_inbound_xrefs(self):
        xrefs = list(self.xrefs)
        xrefs.append(
            XrefRecord(src=0x00401020, dst=None, xref_type="import", instruction="call KERNEL32!VirtualAlloc", src_function=0x00401000, dst_function=None, confidence="medium", api="KERNEL32!VirtualAlloc")
        )
        profiles = build_function_profiles(
            disasm_text=self.disasm,
            functions=self.functions,
            xrefs=xrefs,
            comments={},
            labels={},
            bookmarks=[],
        )
        p = profiles[0x00401000]
        self.assertIn("KERNEL32!VirtualAlloc", p.suspicious_api_usage)
        self.assertEqual(p.inbound_xrefs, 1)

    def test_summary_returns_dict_with_expected_keys(self):
        profiles = build_function_profiles(
            disasm_text=self.disasm,
            functions=self.functions,
            xrefs=self.xrefs,
            comments={},
            labels={},
            bookmarks=[],
        )
        summary = summarize_function_intelligence(profiles, {"0x00401000": "main"})
        self.assertIsInstance(summary, dict)
        for k in (
            "top_risky_functions",
            "functions_with_suspicious_apis",
            "functions_with_interesting_strings",
            "analyst_renamed_functions",
            "commented_or_bookmarked_functions",
        ):
            self.assertIn(k, summary)

    def test_behavior_summary_api_based(self):
        profiles = build_function_profiles(
            disasm_text=self.disasm,
            functions=self.functions,
            xrefs=self.xrefs,
            comments={"0x00401000": "review"},
            labels={},
            bookmarks=[],
        )
        row = generate_function_behavior_summary(profiles[0x00401000])
        self.assertIn("API", row["evidence_bullets"][0])
        self.assertIn(row["confidence"], ("medium", "high"))
        self.assertTrue(row["evidence_bullets"])

    def test_behavior_summary_string_based(self):
        profiles = build_function_profiles(
            disasm_text=self.disasm,
            functions=self.functions,
            xrefs=self.xrefs,
            comments={},
            labels={},
            bookmarks=[],
        )
        row = generate_function_behavior_summary(profiles[0x00401000])
        self.assertIn("string", row["short_behavior_summary"].lower())
        self.assertTrue(any("Referenced strings" in e for e in row["evidence_bullets"]))

    def test_behavior_summary_low_confidence_unknown(self):
        profile = build_function_profiles(
            disasm_text="0x00402000: nop\n0x00402001: ret",
            functions={0x00402000: "sub_402000"},
            xrefs=[],
            comments={},
            labels={},
            bookmarks=[],
        )[0x00402000]
        row = generate_function_behavior_summary(profile)
        self.assertEqual(row["confidence"], "low")
        self.assertIn("unclear", row["short_behavior_summary"].lower())
        all_rows = generate_all_behavior_summaries({0x00402000: profile})
        self.assertIn("0x00402000", all_rows)


if __name__ == "__main__":
    unittest.main()
