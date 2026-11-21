"""Findings model and weighted grading."""

from __future__ import annotations

from dataclasses import dataclass, field

WEIGHTS = {"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}
ORDER = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    remediation: str = ""
    ref: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "ref": self.ref,
        }


@dataclass
class Audit:
    domain: str
    findings: list[Finding] = field(default_factory=list)
    facts: dict = field(default_factory=dict)

    @property
    def score(self) -> int:
        penalty = sum(WEIGHTS.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    @property
    def counts(self) -> dict[str, int]:
        out = {sev: 0 for sev in ORDER}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out

    def sorted_findings(self) -> list[Finding]:
        rank = {sev: i for i, sev in enumerate(ORDER)}
        return sorted(self.findings, key=lambda f: (rank.get(f.severity, 99), f.id))

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "grade": self.grade,
            "score": self.score,
            "counts": self.counts,
            "findings": [f.as_dict() for f in self.sorted_findings()],
            "facts": self.facts,
        }


GRADE_RANK = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1, "?": 0}


def grade_at_least(grade: str, minimum: str) -> bool:
    return GRADE_RANK.get(grade, 0) >= GRADE_RANK.get(minimum.upper(), 0)
