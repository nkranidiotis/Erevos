import unittest

from core.modules.xrefs_foundation import (
    XrefRecord,
    build_code_xrefs_from_text,
    extract_structured_xrefs,
    find_refs_from_function,
    summarize_xrefs,
)


class XrefsFoundationTest(unittest.TestCase):
    def test_structured_xrefs_parse(self):
        txt = "\n".join([
            "0x00401000: mov eax, ebx",
            "0x00401005: call 0x00402000",
            "0x0040100A: jmp 0x00403000",
            "0x0040100F: jne 0x00402000",
            "0x00401014: call qword ptr [rax]",
        ])
        funcs = {0x00401000: "sub_401000", 0x00402000: "sub_402000", 0x00403000: "sub_403000"}
        xrefs = extract_structured_xrefs(txt, functions=funcs)
        self.assertTrue(any(x.xref_type == "call" and x.dst == 0x00402000 for x in xrefs))
        self.assertTrue(any(x.xref_type == "conditional_jump" and x.dst == 0x00402000 for x in xrefs))
        self.assertTrue(any(x.xref_type == "call" and x.dst is None and x.confidence == "low" for x in xrefs))

        x = build_code_xrefs_from_text(txt)
        self.assertEqual(sorted(x[0x00402000]), [0x00401005, 0x0040100F])
        self.assertEqual(x[0x00403000], [0x0040100A])

    def test_string_and_import_refs(self):
        txt = "\n".join([
            "0x00401100: lea rcx, 0x00405000",
            "0x00401105: call KERNEL32!CreateFileW",
            "0x0040110A: call USER32!MessageBoxA",
        ])
        xrefs = extract_structured_xrefs(
            txt,
            strings_by_addr={0x00405000: "http://example.test/c2"},
        )
        self.assertTrue(any(x.xref_type == "string" and x.string_value for x in xrefs))
        self.assertTrue(any(x.xref_type == "import" and x.api == "KERNEL32!CreateFileW" for x in xrefs))

        summary = summarize_xrefs(xrefs)
        self.assertGreaterEqual(summary["unresolved_indirect_calls"], 0)
        self.assertTrue(any(row["api"] == "KERNEL32!CreateFileW" for row in summary["suspicious_api_references"]))
        self.assertTrue(any("example.test" in row["string"] for row in summary["strings_with_references"]))

    def test_refs_from_function(self):
        txt = "0x00401000: call 0x00402000\n0x00401005: jmp 0x00403000"
        refs = find_refs_from_function(txt)
        self.assertIn(0x00402000, refs)
        self.assertIn(0x00403000, refs)


if __name__ == "__main__":
    unittest.main()
