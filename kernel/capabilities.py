"""Layer 3 — least-privilege capabilities.

Authority is minted from the *trusted task*, never from the (possibly injected) plan.
A capability may pin exact argument values (e.g. send_email only to one address).
This is where the CaMeL insight lives: untrusted data may fill VALUES, never expand AUTHORITY.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Symbol:
    """A placeholder in a grant, resolved by the kernel against structural fields only
    (e.g. 'the sender' = the envelope header, never an address from the body)."""
    kind: str


@dataclass(frozen=True)
class Grant:
    """What the trusted authorizer allows, before concrete values are known."""
    tool: str
    scope: dict = field(default_factory=dict)  # values may be Symbol


@dataclass(frozen=True)
class Capability:
    """A concrete, expiring grant to call one tool, optionally pinned to specific arg values."""
    tool: str
    scope: dict
    expires_at: float

    def permits(self, tool: str, args: dict, now: float) -> bool:
        if tool != self.tool or now > self.expires_at:
            return False
        for key, allowed in self.scope.items():
            if args.get(key) != allowed:
                return False
        return True


class CapabilitySet:
    def __init__(self) -> None:
        self._caps: list[Capability] = []

    def mint(self, tool: str, scope: dict, ttl: float = 60.0) -> Capability:
        cap = Capability(tool, dict(scope), time.time() + ttl)
        self._caps.append(cap)
        return cap

    def authorizes(self, tool: str, args: dict) -> bool:
        now = time.time()
        return any(c.permits(tool, args, now) for c in self._caps)
