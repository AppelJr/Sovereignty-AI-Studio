#!/usr/bin/env python3
"""Syntax-Guard — offline syntax validation using LibCST.

No cloud. No exec. No eval. No os.system. No subprocess.
"""

import libcst as cst
import libcst.matchers as m


class SyntaxGuard:
    """Validate and attempt naive repair of Python source."""

    def __init__(self):
        self.blacklist = [
            m.Call(func=m.Name("eval")),
            m.Call(func=m.Name("exec")),
            m.Call(func=m.Name("subprocess")),
            m.Call(func=m.Name("os.system")),
            m.Call(func=m.Name("requests")),
            m.Call(func=m.Name("urllib")),
            m.Assign(),
            m.Import(alias=m.Alias(value=m.Name("socket"))),
            m.Import(alias=m.Alias(value=m.Name("base64"))),
        ]

    def is_valid(self, code_str: str) -> bool:
        """Return True if code_str parses and contains no blacklisted patterns."""
        try:
            tree = cst.parse_module(code_str)
        except Exception:
            return False
        for pattern in self.blacklist:
            if pattern.matches(tree):
                return False
        return True

    def repair(self, broken_code: str, max_tries: int = 3) -> str | None:
        """Super naive repair: add indents, normalize def lines."""
        for _ in range(max_tries):
            candidate = f"    {broken_code.replace('def ', 'def ').replace(':', ': ')}"
            if self.is_valid(candidate):
                return candidate
        return None


if __name__ == "__main__":
    guard = SyntaxGuard()
    raw = "def hello(): print('hi')"
    if not guard.is_valid(raw):
        fixed = guard.repair(raw)
        if fixed:
            print("Fixed:", fixed)
        else:
            print("Can't fix. Burn.")
