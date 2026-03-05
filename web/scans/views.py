import asyncio
import json

from django.shortcuts import render, redirect, get_object_or_404
from django.core.paginator import Paginator
from django.db.models import Q

from threatscout.models.indicator import Indicator

from .forms import ScanForm
from .models import ScanRecord
from .scanner_factory import build_scanner


def index(request):
    """Landing page — scan form + 10 most recent scans."""
    form = ScanForm()
    recent = ScanRecord.objects.all()[:10]
    return render(request, "scans/index.html", {"form": form, "recent": recent})


def scan(request):
    """Run a scan and redirect to the report page."""
    if request.method != "POST":
        return redirect("index")

    form = ScanForm(request.POST)
    if not form.is_valid():
        recent = ScanRecord.objects.all()[:10]
        return render(request, "scans/index.html", {"form": form, "recent": recent})

    raw_value = form.cleaned_data["indicator"].strip()
    indicator = Indicator.detect(raw_value)
    scanner = build_scanner()
    report = asyncio.run(scanner.scan(indicator))
    report_dict = report.to_dict()

    record = ScanRecord.from_report(report_dict)
    record.save()

    return redirect("report", pk=record.pk)


def report(request, pk):
    """Display a saved scan report with card-per-source UI."""
    record = get_object_or_404(ScanRecord, pk=pk)
    data = record.get_report()

    # Group findings by indicator value (original vs enriched)
    original_indicator = data["indicator"]["value"]
    original_findings = []
    enriched_groups = {}
    for f in data.get("findings", []):
        ind_val = f.get("indicator_value", original_indicator)
        if ind_val == original_indicator:
            original_findings.append(f)
        else:
            enriched_groups.setdefault(ind_val, []).append(f)

    return render(request, "scans/report.html", {
        "record": record,
        "data": data,
        "original_findings": original_findings,
        "enriched_groups": enriched_groups,
    })


def history(request):
    """Paginated scan history with search."""
    query = request.GET.get("q", "").strip()
    verdict_filter = request.GET.get("verdict", "").strip()

    qs = ScanRecord.objects.all()
    if query:
        qs = qs.filter(
            Q(indicator_value__icontains=query)
            | Q(indicator_type__icontains=query)
            | Q(resolved_ip__icontains=query)
            | Q(resolved_hostname__icontains=query)
        )
    if verdict_filter:
        qs = qs.filter(verdict=verdict_filter)

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get("page"))

    return render(request, "scans/history.html", {
        "page": page,
        "query": query,
        "verdict_filter": verdict_filter,
    })
