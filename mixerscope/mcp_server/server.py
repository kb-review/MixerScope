"""MCP server exposing the knowledge base and the read-only evidence tools."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mixerscope import __version__
from mixerscope.knowledge_base.loader import UnknownServiceError

from . import tools
from .tools import Settings

INSTRUCTIONS = (
    "mixerscope interprets cryptocurrency-mixer artifacts against a curated knowledge base of service "
    "invariants. All evidence access is read-only. Findings carry provenance (source, locator, method, "
    "origin) and a persistence class; the tool never originates an evidential value. Typical flow: "
    "kb_get_profile or kb_where_is to know what to look for, scan_evidence on each source -> correlate the "
    "scan files -> emit_report. fetch_surface_metadata is "
    "disabled unless the server was started with --allow-network."
)


_ANTICIPATED = (KeyError, ValueError, FileNotFoundError, NotADirectoryError, PermissionError)


def _guard(fn):
    """Turn an anticipated failure (unknown service or fact, missing or unreadable path, bad
    argument) into a ToolError, so the caller reads the reason instead of the library's
    generic "Error executing tool"; anything else stays a crash and is logged as one."""

    def run(*a, **kw):
        try:
            return fn(*a, **kw)
        except _ANTICIPATED as e:
            if isinstance(e, UnknownServiceError):
                msg = f"unknown service {e.args[0]!r}; kb_list_services lists the known ones"
            else:
                msg = e.args[0] if isinstance(e, KeyError) and e.args else str(e)
            raise ToolError(msg) from e

    return run


def build_server(settings: Settings | None = None) -> MCPServer:
    s = settings or Settings()
    server = MCPServer(name="mixerscope", version=__version__, instructions=INSTRUCTIONS)

    @server.tool(name="kb_list_services", description="List the mixer services in the knowledge base with their "
                 "canonical domain, maximum analysed tier and fact count.")
    def kb_list_services() -> list[dict[str, Any]]:
        return _guard(tools.kb_list_services)(s)

    @server.tool(name="kb_get_service", description="Full invariant record of one service (all field groups, each "
                 "field with value, tier, confidence and provenance).")
    def kb_get_service(name: str) -> dict[str, Any]:
        return _guard(tools.kb_get_service)(s, name)

    @server.tool(name="kb_get_artifact_map", description="What a service leaves where: artifacts grouped by "
                 "persistence class, endpoint cache policies, status templates and negative findings.")
    def kb_get_artifact_map(name: str) -> dict[str, Any]:
        return _guard(tools.kb_get_artifact_map)(s, name)

    @server.tool(name="kb_get_profile", description="Investigator profile of one service, built from its entry: "
                 "search terms, where each fact is on disk, how to read it, which absences are expected, what "
                 "lies beyond the disk, and what the entry does not cover; every item with tier, basis and the "
                 "entry field it comes from.")
    def kb_get_profile(name: str) -> dict[str, Any]:
        return _guard(tools.kb_get_profile)(s, name)

    @server.tool(name="kb_where_is", description="One fact of one service (deposit_address, order_id, "
                 "payout_txid, ...): where it is on disk with the artifact, field and recovery route, the "
                 "absences that are expected and why, the on-chain and replay routes, and the full "
                 "fact-by-source matrix row.")
    def kb_where_is(name: str, fact: str) -> dict[str, Any]:
        return _guard(tools.kb_where_is)(s, name, fact)

    @server.tool(name="identify_service", description="Match loose artifacts (URLs, cookie names or name=value, "
                 "file names, strings) against the knowledge base and rank candidate services.")
    def identify_service(artifacts: list[str]) -> dict[str, Any]:
        return _guard(tools.identify_service)(s, artifacts)

    @server.tool(name="scan_evidence", description="Read-only scan of an evidence source (Chrome profile dir, "
                 "files folder or single file, or a strings dump from a disk region) against the knowledge base. "
                 "Writes a scan JSON and returns a summary with its path. For a strings dump pass `location` "
                 "(unallocated, pagefile, filesystem, chrome_cache, chrome_sessions).")
    def scan_evidence(path: str, evidence_type: str | None = None, out_path: str | None = None,
                      max_findings: int | None = None, include_findings: int = 0,
                      location: str | None = None) -> dict[str, Any]:
        return _guard(tools.scan_evidence)(s, path, evidence_type, out_path, max_findings, include_findings,
                                   location=location)

    @server.tool(name="correlate", description="Correlate one or more scan JSON files: identifier roles "
                 "(deposit/destination address, order ID, deposit/payout TXID, client IP), timeline, "
                 "deposit-to-payout triangulation steps, and the KB artifact checklist.")
    def correlate(scan_paths: list[str], out_path: str | None = None) -> dict[str, Any]:
        return _guard(tools.correlate)(s, scan_paths, out_path)

    @server.tool(name="emit_report", description="Render the analyst-reviewable markdown report for one or more "
                 "scan JSON files and write it to disk.")
    def emit_report(scan_paths: list[str], out_path: str | None = None) -> dict[str, Any]:
        return _guard(tools.emit_report)(s, scan_paths, out_path)

    @server.tool(name="fetch_surface_metadata", description="OPT-IN, single GET to https://<domain>/ recording "
                 "status and response headers only (no body, no redirects, no linked pages). Disabled unless the "
                 "server was started with --allow-network.")
    def fetch_surface_metadata(domain: str) -> dict[str, Any]:
        return _guard(tools.fetch_surface_metadata)(s, domain)

    return server


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mixerscope-mcp", description="Run the mixerscope MCP server (stdio).")
    ap.add_argument("--kb", default=str(Settings().kb_path), help="knowledge base SQLite (build it first)")
    ap.add_argument("--out-dir", default="scan_out", help="where scan / correlation / report files are written")
    ap.add_argument("--allow-network", action="store_true",
                    help="enable fetch_surface_metadata (single request, headers only). Off by default.")
    ap.add_argument("--transport", choices=["stdio", "streamable-http", "sse"], default="stdio")
    args = ap.parse_args(argv)
    kb = Path(args.kb)
    if not kb.exists():
        ap.error(f"knowledge base not found: {kb} (run mixerscope-build-kb first)")
    server = build_server(Settings(kb_path=kb, out_dir=Path(args.out_dir), allow_network=args.allow_network))
    server.run(args.transport)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
