from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from secplat.application.reports.model import OverviewReportModel

TEMPLATES_DIR = Path(__file__).parent / "templates"
PDF_MEDIA_TYPE = "application/pdf"
HTML_MEDIA_TYPE = "text/html"
PDF_CONTENT_DISPOSITION = "attachment; filename={name}"
HTML_CONTENT_DISPOSITION = "inline"


def _human_datetime(value: datetime | None) -> str:
    if value is None:
        return "-"
    return value.strftime("%d.%m.%Y %H:%M")


def build_environment() -> Environment:
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["trdt"] = _human_datetime
    return environment


class OverviewHtmlRenderer:
    media_type = HTML_MEDIA_TYPE
    disposition = HTML_CONTENT_DISPOSITION
    filename_suffix = "html"

    def __init__(self) -> None:
        self._environment = build_environment()
        self._template = "overview.html.j2"

    def render(self, model: OverviewReportModel) -> str:
        return self._environment.get_template(self._template).render(model=model)


class OverviewPdfRenderer:
    media_type = PDF_MEDIA_TYPE
    disposition = PDF_CONTENT_DISPOSITION
    filename_suffix = "pdf"

    def __init__(self) -> None:
        self._environment = build_environment()
        self._template = "overview.html.j2"

    def render(self, model: OverviewReportModel) -> bytes:
        from weasyprint import HTML

        html = self._environment.get_template(self._template).render(model=model)
        return HTML(string=html).write_pdf()
