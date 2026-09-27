from __future__ import annotations

from secplat.domain.scanning.errors import UnknownTool
from secplat.domain.scanning.ports import ToolAdapter
from secplat.domain.scanning.value_objects import ToolName
from secplat.infrastructure.config import get_settings
from secplat.infrastructure.tools.checkov.adapter import CheckovAdapter
from secplat.infrastructure.tools.gitleaks.adapter import GitleaksAdapter
from secplat.infrastructure.tools.httpx.adapter import HttpxAdapter
from secplat.infrastructure.tools.nuclei.adapter import NucleiAdapter
from secplat.infrastructure.tools.semgrep.adapter import SemgrepAdapter
from secplat.infrastructure.tools.subfinder.adapter import SubfinderAdapter
from secplat.infrastructure.tools.trivy.adapter import TrivyAdapter


def get_adapter(tool: ToolName) -> ToolAdapter:
    settings = get_settings()
    if tool is ToolName.NUCLEI:
        return NucleiAdapter(binary=settings.nuclei_bin, template_dir=settings.nuclei_template_dir)
    if tool is ToolName.SUBFINDER:
        return SubfinderAdapter(binary=settings.subfinder_bin)
    if tool is ToolName.SEMGREP:
        return SemgrepAdapter(binary=settings.semgrep_bin, workspace_root=settings.workspace_root)
    if tool is ToolName.TRIVY:
        return TrivyAdapter(binary=settings.trivy_bin, workspace_root=settings.workspace_root)
    if tool is ToolName.GITLEAKS:
        return GitleaksAdapter(binary=settings.gitleaks_bin, workspace_root=settings.workspace_root)
    if tool is ToolName.CHECKOV:
        return CheckovAdapter(binary=settings.checkov_bin, workspace_root=settings.workspace_root)
    if tool is ToolName.HTTPX:
        return HttpxAdapter(binary=settings.httpx_bin)
    raise UnknownTool(tool.value)
