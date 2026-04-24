from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict


def compute_hashes(path: str) -> Dict[str, str]:
    """Streaming hashes for forensic integrity."""
    p = Path(path)
    digests = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
        "sha512": hashlib.sha512(),
    }
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for h in digests.values():
                h.update(chunk)

    return {name: h.hexdigest() for name, h in digests.items()}
