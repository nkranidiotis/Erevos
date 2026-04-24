from __future__ import annotations

from typing import Any, Dict

from .triage import analyze_triage


def compare_samples(path_a: str, path_b: str) -> Dict[str, Any]:
    a = analyze_triage(path_a)
    b = analyze_triage(path_b)

    a_hash = a.get('hashes', {})
    b_hash = b.get('hashes', {})

    return {
        'sample_a': {'path': path_a, 'score': a.get('score'), 'verdict': a.get('verdict'), 'hashes': a_hash},
        'sample_b': {'path': path_b, 'score': b.get('score'), 'verdict': b.get('verdict'), 'hashes': b_hash},
        'delta': {
            'score_delta': (b.get('score', 0) or 0) - (a.get('score', 0) or 0),
            'same_imphash': a_hash.get('imphash') and a_hash.get('imphash') == b_hash.get('imphash'),
            'same_sha256': a_hash.get('sha256') and a_hash.get('sha256') == b_hash.get('sha256'),
            'capability_overlap': sorted(
                set((a.get('capabilities') or {}).keys()) & set((b.get('capabilities') or {}).keys())
            ),
        },
    }
