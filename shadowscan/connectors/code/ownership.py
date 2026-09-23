"""Bounded CODEOWNERS glob matching without backtracking regular expressions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

MAX_RULES = 10_000
MAX_PATTERN_LENGTH = 4_096
MAX_OWNERSHIP_STEPS = 10_000_000


class OwnershipLimitError(ValueError):
    """Ownership cannot be resolved within its resource budget."""


@dataclass
class OwnershipBudget:
    remaining: int = MAX_OWNERSHIP_STEPS

    def consume(self, steps: int = 1) -> None:
        self.remaining -= steps
        if self.remaining < 0:
            raise OwnershipLimitError("CODEOWNERS processing budget exceeded")


def _component_match(pattern: str, name: str, budget: OwnershipBudget) -> bool:
    """Match * and ? in bounded O(len(pattern) * len(name)) time/constant space.

    Remember only the most recent star and extend its match if necessary. This
    avoids the exponential search caused by translating overlapping stars to .*.
    """
    p = n = 0
    star = -1
    retry = 0
    while n < len(name):
        budget.consume()
        if p < len(pattern) and pattern[p] == "*":
            star, retry = p, n
            p += 1
        elif p < len(pattern) and (pattern[p] == "?" or pattern[p] == name[n]):
            p += 1
            n += 1
        elif star >= 0:
            retry += 1
            n, p = retry, star + 1
        else:
            return False
    while p < len(pattern) and pattern[p] == "*":
        budget.consume()
        p += 1
    return p == len(pattern)


def codeowners_match(pattern: str, path: str, budget: OwnershipBudget | None = None) -> bool:
    """Match GitHub/GitLab's supported component globs within a shared budget.

    Slash-containing rules are anchored. Bare names and trailing-slash directory
    rules match at any depth; literal directory rules own their descendants.
    The path-level dynamic program is iterative, including for ** components.
    """
    budget = budget if budget is not None else OwnershipBudget()
    if len(pattern) > MAX_PATTERN_LENGTH or len(path) > MAX_PATTERN_LENGTH:
        raise OwnershipLimitError("CODEOWNERS pattern or path exceeds length limit")
    budget.consume(len(pattern) + len(path) + 1)
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    directory = pattern.endswith("/")
    pattern = pattern.strip("/")
    if not pattern or path == ".":
        return False
    parts = PurePosixPath(path).parts
    selectors = pattern.split("/")
    descendants = directory or not any(char in selectors[-1] for char in "*?")
    if not anchored:
        candidates = parts if descendants else parts[-1:]
        return any(_component_match(pattern, part, budget) for part in candidates)

    previous = [True] + [False] * len(parts)
    for selector in selectors:
        current = [False] * (len(parts) + 1)
        if selector == "**":
            current[0] = previous[0]
            for i in range(1, len(parts) + 1):
                budget.consume()
                current[i] = previous[i] or current[i - 1]
        else:
            for i, part in enumerate(parts, start=1):
                budget.consume()
                current[i] = previous[i - 1] and _component_match(selector, part, budget)
        previous = current
    return any(previous[1:]) if descendants else previous[-1]
