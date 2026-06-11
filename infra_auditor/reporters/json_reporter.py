"""JSON report output."""

import json
from typing import List
from ..results import AuditResult


class JSONReporter:
    def __init__(self, pretty: bool = True):
        self.pretty = pretty

    def report(self, result: AuditResult) -> str:
        data = result.to_dict()
        if self.pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)

    def report_all(self, results: List[AuditResult]) -> str:
        data = {
            "audits": [r.to_dict() for r in results],
            "summary": {
                "targets": len(results),
                "total_checks": sum(r.total for r in results),
                "total_passed": sum(r.passed for r in results),
                "total_failed": sum(r.failed for r in results),
            },
        }
        if self.pretty:
            return json.dumps(data, indent=2, default=str)
        return json.dumps(data, default=str)

    def save(self, result: AuditResult, path: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.report(result))
