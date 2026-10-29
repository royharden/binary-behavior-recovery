"""Supplementary exact-byte checks; never proof of semantic independence."""
from __future__ import annotations

from hashlib import sha256


def scan_prompt(prompt: bytes, canaries: tuple[bytes, ...], private_inputs: tuple[bytes, ...]) -> list[dict]:
    if not canaries or any(not c for c in canaries):
        raise ValueError("nonempty committed canary set required")
    findings = []
    for canary in canaries:
        if canary in prompt:
            findings.append({"kind": "canary", "commitment": sha256(canary).hexdigest()})
    # Exact raw private input plus common explicit encodings, never visible hashes.
    for value in private_inputs:
        if not value:
            raise ValueError("empty input cannot be safely substring-scanned")
        commitment = sha256(value).hexdigest()
        if value in prompt or value.hex().encode() in prompt or commitment.encode() in prompt:
            findings.append({"kind": "private_input", "commitment": commitment})
    return findings
