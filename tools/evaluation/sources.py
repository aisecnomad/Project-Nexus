"""Shared exact-source independence checks for the two acceptance gates.

These checks reject known overlap, not establish statistical independence.
Near duplicates and undisclosed prior evaluations still require human review.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from tools.evaluation.evaluate import DEFAULT_CORPUS, Case, load_corpus


class SourceOverlapError(ValueError):
    """Stable codes without private source content, locations, or case IDs."""


def _file_digests(case: Case) -> tuple[set[str], set[str]]:
    # Repeated empty package markers are not repeated independent samples.
    # An entirely blank case still counts as the same blank sample regardless
    # of file names, multiplicity or whitespace, so it cannot inflate a holdout.
    files: set[str] = set()
    samples: set[str] = set()
    for content in case.files.values():
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        files.add(digest)
        if content.strip():
            samples.add(digest)
    return files, samples or {"blank-sample"}


def _locations(case: Case) -> set[tuple[str, str, str]]:
    if not case.source:
        return set()
    return {(case.source["repo"].casefold(), case.source["commit"], case.source["path"])}


@dataclass
class SourceIndex:
    """Bounded corpus hashes and source locations, shared by acceptance tools."""

    corpus_digests: set[str] = field(default_factory=set)
    file_digests: set[str] = field(default_factory=set)
    locations: set[tuple[str, str, str]] = field(default_factory=set)

    def add(self, cases: list[Case], digest: str) -> None:
        self.corpus_digests.add(digest)
        for case in cases:
            self.file_digests.update(_file_digests(case)[0])
            self.locations.update(_locations(case))

    def check_holdout(self, cases: list[Case], digest: str) -> None:
        if digest in self.corpus_digests:
            raise SourceOverlapError("holdout_reuses_evaluated_corpus")
        sample_digests: set[str] = set()
        sample_locations: set[tuple[str, str, str]] = set()
        for case in cases:
            files, samples = _file_digests(case)
            locations = _locations(case)
            # Preserve strict byte/location exclusion against prior corpora,
            # including scaffolding. The blank-file exception only applies to
            # otherwise distinct cases in this holdout.
            if files & self.file_digests or locations & self.locations:
                raise SourceOverlapError("holdout_reuses_evaluated_source")
            if samples & sample_digests or locations & sample_locations:
                raise SourceOverlapError("duplicate_holdout_source")
            # A case is one sampling unit: identical files within the same case
            # do not inflate the sample count. Any nonblank file overlap across
            # cases does, even if file names and other context files differ.
            sample_digests.update(samples)
            sample_locations.update(locations)


def bundled_source_index() -> SourceIndex:
    index = SourceIndex()
    for path in (DEFAULT_CORPUS, *(DEFAULT_CORPUS.with_name(name) for name in (
        "public_corpus.json", "realistic_corpus.json", "independent_corpus.json", "review_corpus.json",
    ))):
        _, cases, digest = load_corpus(path)
        index.add(cases, digest)
    return index
