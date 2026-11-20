"""Call one MCP tool of the mixerscope server over the real stdio transport.

    python scripts/mcp_call.py list
    python scripts/mcp_call.py call kb_list_services
    python scripts/mcp_call.py call kb_where_is name=mixero fact=deposit_address
    python scripts/mcp_call.py call scan_evidence path=<case>/Default --out result.json
    python scripts/mcp_call.py call correlate scan_paths=a.scan.json scan_paths=b.scan.json
    python scripts/mcp_call.py call emit_report scan_paths[]=a.scan.json
    python scripts/mcp_call.py call identify_service @args.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


def _text(res) -> str:
    return "".join(c.text for c in res.content if getattr(c, "text", None))


async def _run(a, tool_args: dict) -> int:
    args = ["--kb", a.kb, "--out-dir", a.out_dir]
    if a.allow_network:
        args.append("--allow-network")
    params = StdioServerParameters(command=a.exe, args=args)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await s.initialize()
            info = init.server_info if hasattr(init, "server_info") else init.serverInfo
            print(f"server: {info.name} {info.version}", file=sys.stderr)
            if a.cmd == "list":
                for t in (await s.list_tools()).tools:
                    print(f"{t.name}")
                    schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None) or {}
                    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
                    req = set(schema.get("required", [])) if isinstance(schema, dict) else set()
                    print("    args: " + ", ".join(f"{k}{'' if k in req else '?'}" for k in props) if props else "    args: none")
                    if t.description:
                        print(f"    {t.description.strip().splitlines()[0]}")
                return 0
            res = await s.call_tool(a.tool, tool_args)
            text = _text(res)
            try:
                text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
            except ValueError:
                pass
            if a.out:
                Path(a.out).write_text(text + "\n", encoding="utf-8", newline="\n")
                print(f"written: {a.out}", file=sys.stderr)
            else:
                print(text)
            if getattr(res, "is_error", None) or getattr(res, "isError", None):
                print("tool returned an error", file=sys.stderr)
                return 1
            return 0


def _tool_args(items: list[str]) -> dict:
    if not items:
        return {}
    if len(items) == 1 and items[0].startswith("@"):
        return json.loads(Path(items[0][1:]).read_text(encoding="utf-8"))
    if items[0].lstrip().startswith("{"):
        try:
            return json.loads(" ".join(items))
        except ValueError as e:
            raise SystemExit(f"the JSON object did not survive the shell ({e}); "
                             "use key=value arguments or @file.json") from e
    out: dict = {}
    for it in items:
        if "=" not in it:
            raise SystemExit(f"argument {it!r} is not key=value; use key=value arguments or @file.json")
        k, v = it.split("=", 1)
        as_list = k.endswith("[]")
        k = k[:-2] if as_list else k
        try:
            val = json.loads(v)
        except ValueError:
            val = v
        if k in out or as_list:
            cur = out.get(k, [])
            out[k] = (cur if isinstance(cur, list) else [cur]) + [val]
        else:
            out[k] = val
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["list", "call"])
    ap.add_argument("tool", nargs="?", help="tool name (for call)")
    ap.add_argument("args", nargs="*", help="tool arguments: key=value ..., one JSON object, or @file.json")
    ap.add_argument("--exe", default=str(ROOT / ".venv" / "Scripts" / "mixerscope-mcp.exe"))
    ap.add_argument("--kb", default=str(ROOT / "build" / "kb.sqlite"))
    ap.add_argument("--out-dir", default=str(ROOT / "cases" / "scan_out"))
    ap.add_argument("--allow-network", action="store_true")
    ap.add_argument("--out", help="write the result to this file instead of stdout")
    a = ap.parse_args(argv)
    if a.cmd == "call" and not a.tool:
        ap.error("call needs a tool name")
    tool_args = _tool_args(a.args) if a.cmd == "call" else {}  # parsed before the server starts
    return asyncio.run(_run(a, tool_args))


if __name__ == "__main__":
    sys.exit(main())
