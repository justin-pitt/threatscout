import json
from django.db import models


class ScanRecord(models.Model):
    """Persisted scan result for history and search."""

    indicator_value = models.CharField(max_length=512, db_index=True)
    indicator_type = models.CharField(max_length=32)
    verdict = models.CharField(max_length=32)
    verdict_confidence = models.IntegerField(default=0)
    query_time_seconds = models.FloatField(default=0.0)
    sources_queried = models.IntegerField(default=0)
    sources_errored = models.IntegerField(default=0)
    resolved_ip = models.CharField(max_length=128, blank=True, default="")
    resolved_hostname = models.CharField(max_length=256, blank=True, default="")
    report_json = models.TextField(help_text="Full report as JSON")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.indicator_value} ({self.indicator_type}) - {self.verdict}"

    def get_report(self) -> dict:
        return json.loads(self.report_json)

    @classmethod
    def from_report(cls, report_dict: dict) -> "ScanRecord":
        ind = report_dict["indicator"]
        return cls(
            indicator_value=ind["value"],
            indicator_type=ind["type"],
            verdict=report_dict["verdict"],
            verdict_confidence=report_dict["verdict_confidence"],
            query_time_seconds=report_dict["query_time_seconds"],
            sources_queried=report_dict["sources_queried"],
            sources_errored=report_dict["sources_errored"],
            resolved_ip=report_dict.get("resolved_ip") or "",
            resolved_hostname=report_dict.get("resolved_hostname") or "",
            report_json=json.dumps(report_dict),
        )
