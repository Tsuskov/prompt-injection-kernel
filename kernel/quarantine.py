"""Layer 2 — the quarantine gate.

Attacker-controlled content never enters the agent's context as free-form text.
It is forced into a fixed schema of *tainted* fields. An imperative injection
('SYSTEM: ignore all instructions...') loses its commanding form once flattened into
{summary, subject, ...}, and whatever survives stays tainted and is never used as a sink.

Crucially, the reply target is taken from the STRUCTURAL header, tagged separately from
body content, so 'reply to the sender' can never mean 'reply to an address in the body'.
"""
from __future__ import annotations

import re

from .provenance import Label, Tainted, Trust


def quarantine_email(email, source: str) -> dict:
    header_label = Label(Trust.UNTRUSTED, confidential=False, sources=frozenset({f"{source}:header"}))
    body_label = Label(Trust.UNTRUSTED, confidential=True, sources=frozenset({f"{source}:body"}))

    # extractive summary only — first sentence, capped length
    summary = re.split(r"(?<=[.!?])\s", email.body.strip())[0][:160]
    # any address the body tries to smuggle in stays tagged as body content
    m = re.search(r"[\w.+-]+@[\w.-]+", email.body)
    injected_addr = m.group(0) if m else ""

    return {
        "from_addr": Tainted(email.from_addr, header_label),   # structural → reply target
        "subject": Tainted(email.subject, body_label),
        "summary": Tainted(summary, body_label),
        "contents": Tainted(email.body, body_label),
        "injected_addr": Tainted(injected_addr, body_label),   # what an injection would offer
    }
