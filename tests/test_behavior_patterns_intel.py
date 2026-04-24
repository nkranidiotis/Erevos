import unittest

from core.modules.behavior_patterns_intel import detect_behavior_patterns


class BehaviorPatternsIntelTest(unittest.TestCase):
    def test_process_injection_pattern(self):
        api_sem = {
            "0x00401000": {
                "api_semantics_calls": [
                    {"api": "KERNEL32!OpenProcess", "call_site": "0x00401010", "interpreted_arguments": ["dwDesiredAccess=0x1F0FFF (estimated)"]},
                    {"api": "KERNEL32!WriteProcessMemory", "call_site": "0x00401020", "interpreted_arguments": ["lpBuffer=payload (estimated)"]},
                    {"api": "KERNEL32!CreateRemoteThread", "call_site": "0x00401030", "interpreted_arguments": []},
                ]
            }
        }
        out = detect_behavior_patterns(api_sem)
        names = {p.get("pattern") for p in out.get("high_confidence_patterns", [])}
        self.assertIn("process injection", names)

    def test_registry_persistence_pattern(self):
        api_sem = {
            "0x00402000": {
                "api_semantics_calls": [
                    {"api": "ADVAPI32!RegOpenKeyExW", "call_site": "0x00402010", "interpreted_arguments": ["lpSubKey=Software\\Microsoft\\Windows\\CurrentVersion\\Run (estimated)"]},
                    {"api": "ADVAPI32!RegSetValueExW", "call_site": "0x00402030", "interpreted_arguments": ["lpValueName=Updater (estimated)"]},
                ]
            }
        }
        out = detect_behavior_patterns(api_sem)
        names = {p.get("pattern") for p in out.get("high_confidence_patterns", [])}
        self.assertIn("persistence via registry", names)

    def test_network_downloader_pattern(self):
        api_sem = {
            "0x00403000": {
                "api_semantics_calls": [
                    {"api": "WINHTTP!WinHttpOpen", "call_site": "0x00403010", "interpreted_arguments": []},
                    {"api": "WINHTTP!WinHttpConnect", "call_site": "0x00403020", "interpreted_arguments": []},
                    {"api": "WINHTTP!WinHttpReadData", "call_site": "0x00403030", "interpreted_arguments": []},
                    {"api": "KERNEL32!CreateFileW", "call_site": "0x00403040", "interpreted_arguments": ["lpFileName=C:/temp/drop.bin (estimated)"]},
                ]
            }
        }
        out = detect_behavior_patterns(api_sem)
        names = {p.get("pattern") for p in out.get("high_confidence_patterns", [])}
        self.assertIn("downloader behavior", names)


if __name__ == "__main__":
    unittest.main()
