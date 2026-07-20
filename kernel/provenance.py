"""Layer 1 — unforgeable provenance labels.

The 'trust bit' the model cannot strip. The label travels with every value and is
set by the KERNEL (transport, tool boundary), never derived from the value's content.
That is the whole point: an attacker controls the *value*, never the *label*.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class Trust(str, Enum):
    TRUSTED = "trusted"      # from the user's request or system config
    UNTRUSTED = "untrusted"  # from data a tool read in from the outside world


@dataclass(frozen=True)
class Label:
    trust: Trust
    confidential: bool = False
    sources: frozenset = frozenset()

    def combine(self, other: "Label") -> "Label":
        worst = Trust.UNTRUSTED if Trust.UNTRUSTED in (self.trust, other.trust) else Trust.TRUSTED
        return Label(worst, self.confidential or other.confidential, self.sources | other.sources)

    def __str__(self) -> str:
        tags = ",".join(sorted(self.sources)) or "-"
        return f"{self.trust.value}{'/confidential' if self.confidential else ''} [{tags}]"


TRUSTED = Label(Trust.TRUSTED)


@dataclass(frozen=True)
class Tainted:
    """A value plus its provenance. The label is authoritative; the value is suspect."""
    value: Any
    label: Label

    def map(self, fn: Callable[[Any], Any]) -> "Tainted":
        return Tainted(fn(self.value), self.label)


def as_trusted(value: Any) -> Tainted:
    return Tainted(value, TRUSTED)
