"""Layer 4 — the deterministic flow policy.

This is the part that gives GUARANTEES independent of model behavior. It breaks the
'lethal trifecta' (private data + untrusted input + egress) at the sink:

  * routing authority is owned by capabilities (see kernel), so destinations are
    always chosen by the trusted task, never by untrusted content;
  * this policy adds the confidentiality rule: confidential data must not leave the
    trust boundary through an egress sink, no matter who asked.

A confirmed violation is an exception, not a probability.
"""
from __future__ import annotations

from .provenance import Tainted
from .tools import ToolSpec


class PolicyViolation(Exception):
    pass


def check_egress(tool: ToolSpec, args: dict) -> None:
    if not tool.egress:
        return
    for p in tool.content_params:
        if p in args and args[p].label.confidential:
            raise PolicyViolation(
                f"Content-Parameter '{p}' wuerde vertrauliche Daten nach aussen tragen "
                f"({args[p].label})"
            )
