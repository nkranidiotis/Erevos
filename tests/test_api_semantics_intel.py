import unittest

from core.modules.api_semantics_intel import interpret_api_semantics


class ApiSemanticsIntelTest(unittest.TestCase):
    def test_virtualalloc_executable_memory_interpretation(self):
        dfi = {"api_argument_insights": [{"api": "KERNEL32!VirtualAlloc", "call_site": "0x401000", "confidence": "high", "arguments": [{"register": "rcx", "value": "0"}, {"register": "rdx", "value": "0x1000"}, {"register": "r8", "value": "0x3000"}, {"register": "r9", "value": "0x40"}]}]}
        out = interpret_api_semantics(dfi)
        self.assertTrue(any("executable_memory" in r.get("capability_tags", []) for r in out["api_semantics_calls"]))

    def test_injection_candidate_openprocess_writeprocessmemory(self):
        dfi = {"api_argument_insights": [
            {"api": "KERNEL32!OpenProcess", "call_site": "0x401100", "confidence": "high", "arguments": [{"register": "rcx", "value": "0x1F0FFF"}]},
            {"api": "KERNEL32!WriteProcessMemory", "call_site": "0x401120", "confidence": "high", "arguments": [{"register": "rcx", "value": "proc_handle"}]},
        ]}
        out = interpret_api_semantics(dfi)
        tags = {t for r in out["api_semantics_calls"] for t in r.get("capability_tags", [])}
        self.assertIn("process_injection_candidate", tags)

    def test_regsetvalue_persistence_candidate(self):
        dfi = {"api_argument_insights": [{"api": "ADVAPI32!RegSetValueExA", "call_site": "0x401200", "confidence": "high", "arguments": [{"register": "rcx", "value": "HKEY_CURRENT_USER"}, {"register": "rdx", "value": "Software\\Microsoft\\Windows\\CurrentVersion\\Run"}]}]}
        out = interpret_api_semantics(dfi)
        self.assertTrue(any("persistence_registry_candidate" in r.get("capability_tags", []) for r in out["api_semantics_calls"]))

    def test_winhttp_network_candidate(self):
        dfi = {"api_argument_insights": [{"api": "WINHTTP!WinHttpOpen", "call_site": "0x401300", "confidence": "high", "arguments": [{"register": "rcx", "value": "http://example.test"}]}]}
        out = interpret_api_semantics(dfi)
        self.assertTrue(any("network_communication_candidate" in r.get("capability_tags", []) for r in out["api_semantics_calls"]))

    def test_isdebuggerpresent_anti_debug_candidate(self):
        dfi = {"api_argument_insights": [{"api": "KERNEL32!IsDebuggerPresent", "call_site": "0x401400", "confidence": "high", "arguments": []}]}
        out = interpret_api_semantics(dfi)
        self.assertTrue(any("anti_debugging_candidate" in r.get("capability_tags", []) for r in out["api_semantics_calls"]))


if __name__ == "__main__":
    unittest.main()
