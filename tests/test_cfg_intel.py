import unittest

from core.modules.cfg_intel import build_function_cfg_model, analyze_function_cfg


class CfgIntelTest(unittest.TestCase):
    def test_synthetic_cfg_block_extraction_and_edges(self):
        txt = "\n".join([
            "0x00401000: cmp eax, ebx",
            "0x00401002: jne 0x00401010",
            "0x00401007: mov ecx, eax",
            "0x00401009: jmp 0x00401020",
            "0x00401010: xor eax, eax",
            "0x00401012: jmp 0x00401020",
            "0x00401020: ret",
        ])
        cfg = build_function_cfg_model(txt, function_start=0x00401000)
        self.assertGreaterEqual(len(cfg["basic_blocks"]), 3)
        types = {e["edge_type"] for e in cfg["edges"]}
        self.assertIn("conditional_true", types)
        self.assertIn("conditional_false", types)
        self.assertIn("unconditional_jump", types)
        self.assertIn("return", types)

    def test_loop_and_back_edge_detection(self):
        txt = "\n".join([
            "0x00402000: cmp ecx, 0",
            "0x00402003: je 0x00402010",
            "0x00402008: dec ecx",
            "0x0040200A: jmp 0x00402000",
            "0x00402010: ret",
        ])
        cfg = build_function_cfg_model(txt, function_start=0x00402000)
        a = analyze_function_cfg(cfg)
        self.assertTrue(a["loop_back_edge_hints"])
        self.assertIn("loop_back_edges_present", a["suspicious_control_flow_indicators"])


if __name__ == "__main__":
    unittest.main()
