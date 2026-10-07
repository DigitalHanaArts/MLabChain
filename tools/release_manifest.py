#!/usr/bin/env python3
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='Write SHA-256 release manifest for Mera artifacts')
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--output', default='SHA256SUMS')
    a = ap.parse_args()
    out = Path(a.output)
    lines = [f'{sha256(Path(x))}  {Path(x)}' for x in a.paths]
    out.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(out.resolve())
