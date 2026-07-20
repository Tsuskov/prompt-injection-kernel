"""The security kernel — ties the layers together.

For every proposed tool call it enforces, in order:
  1. Capability authorization — is this call covered by authority minted from the
     TRUSTED task? Symbolic grants ('the sender') are resolved from structural headers
     only, so untrusted content can never expand what the agent is allowed to do.
  2. Deterministic flow policy — no confidential payload crosses an egress sink.
Untrusted tool output is quarantined before it is ever bound and reused.

A rejected call raises Blocked. Nothing executes past the check.
"""
from __future__ import annotations

from .capabilities import CapabilitySet, Symbol
from .planner import Ref
from .policy import PolicyViolation, check_egress
from .provenance import Tainted, as_trusted
from .quarantine import quarantine_email


class Blocked(Exception):
    pass


class Kernel:
    def __init__(self, tools: dict, grants: list, *, verbose: bool = True):
        self.tools = tools
        self.grants = grants
        self.caps = CapabilitySet()
        self.bindings: dict = {}
        self.symbols: dict = {}
        self.verbose = verbose
        # mint capabilities that need no runtime resolution up front
        for g in grants:
            if not any(isinstance(v, Symbol) for v in g.scope.values()):
                self.caps.mint(g.tool, g.scope)

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg)

    def _resolve(self, v) -> Tainted:
        if isinstance(v, Ref):
            cur = self.bindings[v.name]
            for key in v.path:
                cur = cur[key]
            return cur if isinstance(cur, Tainted) else as_trusted(cur)
        return as_trusted(v)

    def _mint_symbolic(self) -> None:
        """Turn symbolic grants into concrete capabilities once their symbols resolve."""
        for g in self.grants:
            if not any(isinstance(x, Symbol) for x in g.scope.values()):
                continue
            resolved, ok = {}, True
            for k, x in g.scope.items():
                if isinstance(x, Symbol):
                    if x.kind in self.symbols:
                        resolved[k] = self.symbols[x.kind]
                    else:
                        ok = False
                        break
                else:
                    resolved[k] = x
            if ok and not self.caps.authorizes(g.tool, resolved):
                self.caps.mint(g.tool, resolved)
                self._log(f"   ↳ Capability erteilt: {g.tool} {resolved}")

    def run(self, plan: list) -> str:
        for call in plan:
            spec = self.tools[call.tool]
            args = {k: self._resolve(v) for k, v in call.args.items()}
            raw = {k: t.value for k, t in args.items()}

            # 1. capability authorization (authority from the trusted task, not the plan)
            self._mint_symbolic()
            if not self.caps.authorizes(call.tool, raw):
                raise Blocked(f"Keine Capability fuer {call.tool} {raw}")

            # 2. deterministic flow policy
            try:
                check_egress(spec, args)
            except PolicyViolation as e:
                raise Blocked(str(e))

            # 3. execute
            result = spec.fn(**raw)
            shown = ", ".join(f"{k}={v!r}" for k, v in raw.items())
            self._log(f"   ✓ {call.tool}({shown})")

            # 4. quarantine untrusted output before binding it for later use
            if call.bind and spec.reads_untrusted:
                fields = quarantine_email(result, source="email")
                self.bindings[call.bind] = fields
                self.symbols["reply_target"] = fields["from_addr"].value
                self._log(f"   ↳ Quarantaene: reply_target = "
                          f"{self.symbols['reply_target']!r} (nur aus Header)")
            elif call.bind:
                self.bindings[call.bind] = as_trusted(result)
        return "OK"
