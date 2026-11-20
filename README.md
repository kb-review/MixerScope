# mixerscope

Read-only forensic interpretation layer for cryptocurrency-mixer artifacts.

*Existing tools extract; this system interprets.* Mature parsers (Chrome artifact tools,
Autopsy, SQLite viewers) already pull browser and file-system artifacts off a disk image, but
they are service-agnostic: they do not know what a mixer's artifacts *mean*. mixerscope adds
the missing layer: a curated, cross-service knowledge base (KB) of how web-based mixers behave
and what they leave on a device, plus tooling to match evidence against it. It never
reimplements a parser; it wraps them.

This repository is the tooling pillar of a research project whose output is a cross-service
host-forensic taxonomy of mixers, tooling, and empirical behavioural findings. **The knowledge base is written by the analyst, by hand, one YAML file per service. The
tooling starts after that**: schema validation, the SQLite build and loader, the read-only
disk-evidence scanner, correlation and reporting, and the MCP server that exposes them. See
[Roadmap](#roadmap) for what comes next.

## The four rules

Everything in this codebase follows from four decisions. Code review should restate them.

### 1. Invariants in the KB, instance data elsewhere

The KB stores **service invariants**: things true of *every* transaction through a service.
It never stores **instance data**: facts about one particular transaction.

| Invariant (KB) | Instance (per-case findings, never the KB) |
| --- | --- |
| order ID follows PHP `uniqid`, regex `^[0-9a-f]{14}\.\d+$` | a specific order ID |
| status endpoint is `POST /Home/check_transaction`, keyed by deposit address | a specific deposit address |
| completion response matches `Transaction has been completed with TXID: [0-9a-f]{64}` | a specific payout TXID |
| session cookie is named `ci_session` | a cookie value |

Validation enforces this. A field value containing a 64-hex hash, a bech32 or base58
address, an EVM address, a uniqid-shaped token or an ISO timestamp fails with a message that
points to the case-findings output. Regex-typed fields (`Pattern`) are exempt because a regex
*describes* a class of values. A genuine literal invariant that looks like instance data (for
example a service's fixed guarantee-signing address) must be declared with
`invariant_literal: "<reason>"` on the record.

### 2. Tiered collection: a service can be partially known

Real transactions cost money, and most of an entry does not need one. A tier is the stage of
the transaction at which a fact can first be established; the observation kind (capture, disk
image, operator page, replay, explorer) records how it was seen.

| Tier | What it takes | What it establishes |
| --- | --- | --- |
| 0 no_funds | public pages, an order created behind a proxy, the invoice, the letter download; nothing funded | domains, CDN, framework, operator claims, endpoints, cookies, order-ID scheme, status mechanism and its first state, the letter template, and every disk artifact that exists once the order is created |
| 1 funded | a real deposit goes through; the host acquired afterwards; optional replay | post-payment status templates (deposit TXID, payout TXID), which post-payment facts reach disk at all, the explorer visit, on-chain structure and fee arithmetic, replay behaviour and observed retention |

A Tier-0-only entry is a valid, first-class record. Whether funding adds
disk artifacts is itself a per-service finding, which is why the two tiers stay separate even
for a service like Mixero where Tier 1 added almost nothing on disk. The full definitions are
in `mixerscope/knowledge_base/tiers.yaml`.

### 3. Read-only, with provenance on everything

Nothing here acquires, modifies or writes to evidence. Every asserted value in the KB cites
observations, and every observation carries a **provenance class**: `subject_evidence`
(would exist on a seized disk), `instrumentation` (lab-only: a proxy capture, a replay),
`operator_claim` (the service's own statements) or `public_record` (blockchain, explorer).
Every scan finding carries its source path, locator, extraction method and the source file's
hash. The tool labels and organises; it never originates an evidential value. There is no
inferring or "correcting" of addresses or hashes anywhere.

### 4. No crawler; entries are the analyst's, drafted under their review

The KB is curated by the analyst from their own controlled experiments: captures, downloaded
documents, operator pages and the acquired disk. Nothing in this repository crawls a service.
An entry is written by hand: every value cites an observation or is marked unknown, the
entry stays `draft` until it has been reviewed, and nothing in it is generated from the KB's
own build or from the tool's scans. The only live contact is the explicitly opt-in, single-request
`fetch_surface_metadata(domain)` MCP tool, which records the status and response headers of
one GET and nothing else: no body, no redirects, no linked pages. It is refused unless the
server is started with `--allow-network`.

## Install

Requires Python 3.11 or newer (developed on 3.14). No `uv` needed.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

On POSIX shells substitute `./.venv/bin/python`.

## Run

Build the SQLite knowledge base from the YAML seeds (YAML is the source of truth; the
database is a regenerated build product and is gitignored):

```powershell
.\.venv\Scripts\mixerscope-build-kb.exe            # writes build\kb.sqlite
# or: python -m mixerscope.knowledge_base.build --out build\kb.sqlite
```

Query it from Python:

```python
from mixerscope.knowledge_base.loader import KnowledgeBase

with KnowledgeBase.open("build/kb.sqlite") as kb:
    kb.list_services()                    # summaries with max tier and fact counts
    entry = kb.get_service("mixero")      # full validated ServiceEntry
    kb.get_artifact_map("mixero")         # artifacts by persistence class, cache policies, templates
    kb.find_by_domain("mixero.co")        # -> [{"service": "mixero", "role": "asset"}]
    kb.patterns(kind="status_template")   # regexes for the matching engine
    kb.facts("mixero", tier=1)            # flattened facts with provenance
```

The loader opens the database read-only. Regenerate the JSON Schema for documentation with
`python -m mixerscope.schema.jsonschema` (output in `docs/`).

### Scan evidence

Match evidence against the knowledge base, read-only. Every finding carries the source
file, a locator inside it (table row, byte offset, line, exchange index), the extraction
method, the origin tag, and the KB artifact it evidences with its persistence class and
recovery routes.

```powershell
.\.venv\Scripts\mixerscope-scan.exe "<case>\Chrome\User Data\Default"                       # Chrome profile dir
.\.venv\Scripts\mixerscope-scan.exe "<case>\Downloads" --type files                          # loose files (a single file works too)
.\.venv\Scripts\mixerscope-scan.exe unalloc.strings --type strings --location unallocated     # strings -t d over a disk region
```

Adapters and what they read:

- **Chrome profile**: History (urls, visits, downloads, download URL chains), Cookies
  (names, hosts, flags, timestamps; values only when stored in plaintext, never decrypted),
  Web Data autofill, Local Storage and Session Storage LevelDB files, Cache blocks and
  Sessions (session-restore) files. SQLite is opened with `mode=ro&immutable=1`, which takes
  no lock and never creates journal files; the other files are carved for printable strings.
  A `-wal` file beside a database is carved separately and reported.
- **Files**: file names (for filename patterns), the whole text of small files (for document
  templates such as a letter of guarantee) and carved strings of files up to 8 MB.
- **Strings dump**: a text file produced by another tool, one string per line, with the
  offset as locator when present. You state the disk region it came from with `--location`
  (`unallocated`, `pagefile`, `filesystem`, `chrome_cache`, `chrome_sessions`); artifacts
  recorded at that location can then match.

Matching rules come straight from the KB entries: `indicators` (weighted identification
signatures), domains with roles, endpoint path patterns whose `field_facts` label the values
in query strings and carved request bodies, cookie names whose `encodes_fact` labels a
plaintext value, status templates whose `yields` label captured TXIDs and amounts, and
artifacts gated on the candidate's location (an autofill field name or a session-restore
string only matches artifacts recorded at that location) whose `carries_facts` label tokens
when unambiguous. Every finding is a case-findings record: fact, value, `artifact_ref`,
location, persistence class, and a source block with path, locator, method and the source
file's sha256. Candidates that match nothing but carry an evidence-class token stay as
service-less `token:` findings. The service ranking ignores services backed only by weak
rules such as generic cookie names or bare address schemes.

Output is `scan_out/<name>.scan.json` (gitignored). `scripts/validate_recovery.py` compares
one or more scan files with a ground-truth file kept outside the repository and reports
which values were recovered, from where, and whether the fact label was right.

### Run the MCP server (phase 4)

```powershell
.\.venv\Scripts\mixerscope-build-kb.exe                       # once, or after editing a seed
.\.venv\Scripts\mixerscope-mcp.exe --kb build\kb.sqlite       # stdio transport
```

Client configuration (any MCP client):

```json
{"mcpServers": {"mixerscope": {"command": "<repo>/.venv/Scripts/mixerscope-mcp.exe",
                               "args": ["--kb", "<repo>/build/kb.sqlite",
                                        "--out-dir", "<case>/scan_out"]}}}
```

Tools:

| Tool | What it does |
| --- | --- |
| `kb_list_services` | services with canonical domain, max analysed tier, fact count |
| `kb_get_service(name)` | the full invariant record with tier, confidence and provenance per field |
| `kb_get_artifact_map(name)` | artifacts by persistence class, cache policies, status templates, negative findings |
| `kb_get_profile(name)` | the investigator profile: six questions, every item with tier, basis and entry field |
| `kb_where_is(name, fact)` | one fact: disk artifacts with recovery routes, expected absences, on-chain and replay routes, matrix row |
| `identify_service(artifacts)` | rank services for loose URLs, cookie names, file names or strings |
| `scan_evidence(path, evidence_type?)` | read-only scan; writes a scan JSON, returns a summary and its path |
| `correlate(scan_paths)` | identifier roles, timeline, deposit-to-payout triangulation, KB artifact checklist |
| `emit_report(scan_paths)` | analyst-reviewable markdown report |
| `fetch_surface_metadata(domain)` | opt-in single GET, headers only; refuses unless started with `--allow-network` |

To exercise one tool at a time without an agent, `scripts/mcp_call.py` starts the server
over stdio exactly as a client would and calls a single tool:

```powershell
.\.venv\Scripts\python.exe scripts\mcp_call.py list
.\.venv\Scripts\python.exe scripts\mcp_call.py call kb_where_is name=mixero fact=deposit_address
.\.venv\Scripts\python.exe scripts\mcp_call.py call scan_evidence path=<case>/Default --out scan.json
.\.venv\Scripts\python.exe scripts\mcp_call.py call correlate scan_paths=a.scan.json scan_paths=b.scan.json
```

Arguments are `key=value` pairs (a repeated key becomes a list), a JSON object, or `@file.json`;
on Windows PowerShell 5.1 use the first or the last, because the shell strips the quotes out
of a JSON object. An anticipated failure (unknown service or fact, missing path) comes back
as a tool error carrying its reason; the script exits 1.

Correlation classifies addresses by the KB's `field_roles` on endpoints (which query
parameter or form field is the deposit address, which is a destination) and by the
`field_names` an artifact is stored under in autofill, never by guessing. The one derived value
is the order-creation time computed from a uniqid order ID, and it is labelled *derived*
everywhere. Triangulation lists the on-chain steps for the analyst to run; the tool itself
never queries a chain or an explorer, and the "where to look" hints in those steps are read
from the identified service's matrix row, not from a list in the code.

### Consistency checks and investigator profiles

The build refuses an entry whose artifacts and matrix cells disagree
(`mixerscope/knowledge_base/consistency.py`): an artifact that carries a fact needs a
`recovered` or `metadata_only` cell in its column, a `not_stored_by_design` finding allows no
`recovered` cell in that column, and every row's artifact list must name existing artifacts.
After loading, the build writes an investigator profile per service to `profiles/` next to the
database, as JSON and Markdown (`mixerscope/knowledge_base/profile.py`): the entry re-read along
an investigator's six questions, every item with its tier, basis and the entry field it comes
from. The profile adds no text of its own; the Markdown layout and labels come from
`views/profile_view.yaml`, and the renderer refuses any string that is in neither the entry,
the definitions nor the view.

## Test

```powershell
.\.venv\Scripts\python.exe -m pytest
```

The suite covers: the Fact wrapper and provenance rules, the instance-data guards, that the
shipped seed files validate and contain no instance data (a raw-text scan), that Mixero is
fully tiered, that injecting a TXID or address into a
seed fails validation, the YAML to SQLite to loader round trip, read-only enforcement, and
that the build refuses to overwrite a file it did not create.

No configuration or environment variables are required.

## Layout

```text
mixerscope/
  schema/            fact.py (Fact/Observation/Tier/Confidence/Pattern), provenance.py,
                     guards.py (instance-data detectors), service.py (field groups),
                     jsonschema.py (export)
  knowledge_base/    services/*.yaml (seed entries), build.py (YAML -> SQLite),
                     loader.py (read-only API), __init__.py (YAML loading),
                     consistency.py (cross-field checks), profile.py (investigator profiles)
views/               profile_view.yaml (layout and labels of the investigator profile)
  evidence/          adapters/ (chrome, files, strings), carve.py (string carving),
                     tokens.py (evidence-class token detection), findings.py (Candidate /
                     Finding / ScanResult), matcher.py (KB rules + identify_service), cli.py
scripts/             validate_recovery.py (ground truth vs scan results), kb_tables.py
                     (tables rendered from an entry), mcp_call.py (one MCP tool over stdio)
  mcp_server/        server.py (MCPServer + CLI), tools.py (plain-Python tool bodies),
                     correlate.py (roles, timeline, triangulation, checklist), report.py
docs/                generated JSON Schema; profiles/ holds the investigator profiles built
                     from the three entries (JSON and Markdown, regenerated by the KB build)
tests/
```

## Schema v0.4 at a glance

One YAML file per service. Every code a service file may use (tiers, basis, facts,
locations, matrix columns and cell words, cache policies, gate mechanisms, indicator kinds,
placeholders ...) is defined once, with a label and a meaning, in
[mixerscope/knowledge_base/definitions.yaml](mixerscope/knowledge_base/definitions.yaml).
The same file lists the building blocks every value is written in (attribute, validity,
observation, pattern, template, invariant literal, matrix cell) with the meaning of each
field, so the file is the complete written form of the schema's building blocks. The
Python enums and models mirror it and the test suite fails if either drifts; the built KB
carries the definitions and the renderers take their labels from them. The full structural
definition is in [docs/](docs/) as JSON Schema; the Python models are in
[mixerscope/schema/](mixerscope/schema/).

- **§A Attribute.** Every fact is `{value, tier (0 no funds / 1 funded), basis, sources, validity?, notes?}`.
  `basis` is `observed`, `inferred`, `claimed` (the operator says so) or `unknown`.
  `sources` are observation ids, required unless unknown. `validity` records when the
  value was true (`first_seen`, `last_seen`, `status`, `superseded_by`); a service-level
  `validity_default` covers attributes without their own, so a superseded front end is
  dated rather than overwritten.
- **§S Observations.** A registry at the top of each file: id, kind (capture_flow,
  disk_image, operator_page, replay, explorer), provenance class (subject_evidence,
  instrumentation, operator_claim, public_record), tier, date, OS and browser version, and a
  pointer to the case file. Validation checks that every cited id exists, that no attribute
  claims a higher tier than its sources, and that `claimed` cites an operator source.
- **§P Placeholders.** Patterns and Templates use `<btc_address>`, `<txid_hex64>`,
  `<order_id>`, `<amount_btc>`, `<unix_ts>`, `<ipv4>` and friends instead of values; a
  Template such as `Transaction has been completed with TXID: <txid_hex64>` records which
  facts it `yields`. A service-level literal that looks like instance data (signing key,
  onion) is an `InvariantLiteral` with a justification.
- **§V Vocabularies.** Fourteen canonical facts (deposit_address, destination_address,
  order_id, receipt, deposit_txid, payout_txid, amounts, fee_and_delay, mix_mode,
  order_created_time, session_id, client_ip, user_identifier, status_progression), fourteen artifact locations
  (chrome_history ... filesystem, pagefile, unallocated, on_chain, network_only),
  persistence classes (disk, on_chain, none_by_design), cache policies, status mechanisms.
  Live memory is deliberately not modelled: the knowledge base describes what a
  post-incident investigator can recover from the acquired disk; a fact that only existed
  in a no-store response is `none_by_design` on disk and is reconstructed on-chain.
- **Sections.** `service`, `identity` (domains with roles, CDN, framework, IP leak),
  `access` and `modes`, `order_model.identifiers` (schemes, derivation, roles, where
  exposed), `cookies` (names, flags, rotation, what the value encodes), `endpoints` (path
  pattern, request field names, `field_facts`, gate (a list of mechanisms: session, csrf,
  captcha), ownership check, cache policy, response
  templates, and `replay_results` for the four-request replay protocol), `status`
  (mechanism, interval, ordered states), `receipts` (how a letter of guarantee is obtained,
  its file, structure as content templates, signature and evidentiary value), `artifacts`
  (location, path and filename patterns, producer, carried facts, persistence, recovery
  route, search keys), `fact_coverage` (the stored fact-by-source matrix), `retention`
  (claimed vs observed), `negative_findings` (each with its absence value), `indicators`
  (weighted identification signatures: domain, cookie name, URL path, filename, string,
  header; a string or domain indicator may be an invariant literal) and `extensions`.
- **The fact-by-source matrix.** One row per canonical fact, one cell per source an
  investigator can hold (history, downloads, cache, cookies, web storage, autofill, session
  restore, file system, server replay, blockchain). A cell is one of `recovered`,
  `metadata_only` (the row exists, the value is encrypted or unreadable), `live_only`,
  `required_to_query` (you must already hold the fact to ask this source),
  `not_stored_by_design`, `not_found`, `not_tested` or `not_applicable`, optionally with a
  detail after a colon. Dead-box recoverability is derived from the disk columns. The
  scanner's checklist compares each row's `recovered` cells with where the fact was in fact
  found. `scripts/kb_tables.py` renders the matrix, the observation registry, replay results,
  YAML excerpts and any definitions vocabulary as markdown for the paper.

**Document templates.** An artifact such as a Letter of Guarantee carries its full text as a
Template with placeholders, one per variant. The letter's wording, section markers, signing
key and signature format are service invariants; the addresses, amounts, order ID and date
are placeholders whose facts are listed in `yields`. The scanner parses any recovered copy,
in a Downloads folder, a cache block or unallocated space, into labelled facts, which is
what tells the deposit address from the destination inside the same file. Letter phrases
also make the strongest identification indicators.

## Adding a new service

1. Run the Tier-0 experiment: read the operator's pages, create an order behind a capturing
   proxy, reach the invoice, download the letter. Optionally fund it (Tier 1) and acquire
   the disk afterwards.
2. Start a new `mixerscope/knowledge_base/services/<id>.yaml` from `mixero.yaml`. Register each source as an observation first, then write the
   sections from what you saw: identity and cookies from the capture, endpoints with
   `field_facts`, the status states as Templates, the letter as a content template, modes
   from the operator's pages with `confidence: claimed`, and, once the disk is examined,
   `artifacts`, `fact_coverage`, `retention` and `negative_findings`. Running
   `mixerscope-scan` on the profile copy against your ground truth shows where facts land.
3. Keep instance data out. Use placeholders in patterns and templates and
   `InvariantLiteral` for genuine service constants; the build rejects anything that looks
   like one transaction's value.
4. Run `pytest` (the seed tests pick up every file) and rebuild the KB. The validator reports
   dangling observation ids, tiers above their sources, and claims without an operator source.

## Roadmap

- **Evidence matcher** (done): Chrome profile, files and strings-dump adapters; KB matching;
  service identification; recovery validation script.
- **MCP server** (done): all eight tools over stdio or HTTP transports.
- **Knowledge-base authoring** is manual by decision; no drafting from captures.
- **Validation** (done for Mixero): 3 of 5 ground-truth values recovered
  from the Chrome profile and the downloaded letter, each labelled with the right fact; the
  two misses (sending address, payout TXID) are what the KB predicts for a disk.
- **Next**: adapters for Firefox and for extracted Chrome artifact exports; tier-conditional
  completeness checks.
