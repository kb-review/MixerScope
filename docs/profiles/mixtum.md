# Mixtum: Investigator profile

**Scope of this profile.** entry status: *reviewed*; tiers: 0; valid: 2026-10 to 2026-10; environment: Windows 10, Chrome 156; acquisition conditions: Chrome closed normally; VM shut down normally before acquisition. The profile also holds the analyst's rehearsal of the same procedure on the evening before and the morning of the capture, without the proxy: visits, two earlier letter downloads (test mode and mix mode) in the download rows, and one earlier mix-mode POST body in session restore; the Downloads folder holds the capture's two letters. The analyst viewed the capture in the mitmproxy web interface inside the same profile; its History rows and cache entries (127.0.0.1:8081) are instrumentation and were excluded from every disk claim..

Tier/Basis: the number is the collection tier, the letter the evidence basis (O observed, I inferred, C claimed, U unknown). Every row names the entry field it comes from.

## 1. Was this service used? (search terms, strongest first)

| Search for | Kind | Tier/Basis | From |
|---|---|---|---|
| `mixtum.io` | domain | 0/O | `indicators[0]` |
| `mixtumjzn2tsiusfkdhutntamspsg43kgt764qbdaxjebce4h6fcfiad.onion` | text string | 0/C | `indicators[1]` |
| `MixTum has generated the address` | text string | 0/O | `indicators[2]` |
| `D3B280956F0E7CAF` | text string | 0/O | `indicators[3]` |
| `63DFE7F602E8C7D50B1D2340FDAEC8327BBC8E99` | text string | 0/O | `indicators[4]` |
| `^MixTum_guarantee_letter( \(<int>\))?\.txt$` | file name | 0/O | `indicators[5]` |
| `Created New Order \\| MixTum\.io` | text string | 0/O | `indicators[6]` |
| `level=<int>&forward_addr=<btc_address>&forward_addr2=` | text string | 0/O | `indicators[7]` |
| `Mixing mode: Complete anonymity\|Operation mode: Precise Payment` | text string | 0/O | `indicators[9]` |
| `^/(en\|ru\|de)/mix(\?mode=(mix\|amount\|test))?$` | URL path | 0/O | `indicators[8]` |
| `challenges\.cloudflare\.com/\^0https://mixtum\.io` | text string | 0/O | `indicators[10]` |
| `Powered by Jambler\.io` | text string | 0/O | `indicators[11]` |
| `^cf_clearance$` | cookie name (weak: shared with unrelated sites) | 0/O | `indicators[12]` |
| `^server:\s*cloudflare$` | response header (weak: shared with unrelated sites) | 0/O | `indicators[13]` |

| Domain | Role | Tier/Basis | From |
|---|---|---|---|
| `mixtum.io` | canonical | 0/O | `identity.domains[0]` |
| `mixtumjzn2tsiusfkdhutntamspsg43kgt764qbdaxjebce4h6fcfiad.onion` | onion | 0/C | `identity.domains[1]` |

## 2. Where each fact is on the disk

| Facts (where in the record) | Location | Field | Recovery | Caveat | Tier/Basis | From |
|---|---|---|---|---|---|---|
| **Deposit address**: letter body; **Destination address**: letter body (destination and, in the amount mode, change address); **Letter of Guarantee**: the letter file; **Mixing mode**: 'Mixing mode' or 'Operation mode' line of the letter; **Order time**: 'valid for 168 hours from <datetime> GMT' in the letter body (printed two hours ahead of UTC), the signature packet's creation time (UTC) and the file timestamps | File system | `<Downloads>/MixTum_guarantee_letter.txt (Chrome adds ' (<int>)' before the extension for repeated downloads)` | User's Downloads folder; the body carries the deposit address, the destination (and change) address, the mode name and the offer start time, and the signature packet carries the signing time in UTC. The fixed file name is the search key; search unallocated space for 'MixTum has generated the address'. The download row's start time and tab URL pair each file with its order. |  | 0/O | `artifacts.letter_file` |
| **Destination address**: forward_addr in the mix-mode POST body; absent for the amount-mode order, whose submission was re-posted through the CDN challenge with the token as its only body field; **Mixing mode**: level=<int> in the POST body and the mode parameter of the navigation URL | Session restore | `Sessions/Session_<int> and Sessions/Tabs_<int> (SNSS)` | The navigation entry for a direct form submission keeps the POST body as ASCII (level=<int>&forward_addr=<btc_address>&forward_addr2=...) next to the page URL. When Cloudflare's challenge intercepts the submission, the entry kept is the re-post, whose body is only the challenge token field, so the addresses and amount are absent. No typed form state in UTF-16 was found. | Chrome 156 also writes a Sessions_Encrypted folder; if later versions stop writing plaintext session files, the POST bodies may no longer be readable from Sessions/. | 0/O | `artifacts.session_restore_state` |
| **Letter of Guarantee**: download row (fixed file name, blob URL, tab URL with the mode, start time); **Mixing mode**: mode parameter in the download row's tab URL; **Order time**: download start time (follows creation by a user action) | Downloads | `History: downloads.target_path, downloads.tab_url (https://mixtum.io/en/mix?mode=<mix_mode>), downloads_url_chains.url (blob:https://mixtum.io/<text>)` | Chrome History DB, downloads and downloads_url_chains tables: one row per letter download with the file name, the tab URL whose mode parameter names the mode, a blob: URL and the start time (follows order creation by a user action); one row per download. |  | 0/O | `artifacts.letter_download_record` |
| **Mixing mode**: mode parameter of the visited /en/mix?mode=<mode> URL, with the title 'Created New Order' on the order page visit; **Order time**: visit time of the order page (same URL as the form), recorded at submission | History | `History: urls.url and visits.visit_time for /en/mix and /en/mix?mode=<mix_mode>` | Chrome History DB: the order page has the same URL as its form (/en/mix?mode=<mode>), so the visit recorded at submission time is the order creation and the mode parameter names the mode. No URL carries an address or the letter. Cloudflare challenge redirects add visits with __cf_chl_tk / __cf_chl_rt_tk query tokens and the title 'Just a moment...'. | The urls row keeps the title of the last visit only: 'Created New Order \| MixTum.io' when the order page was the last visit of that URL, 'Create New Order \| MixTum.io' when the form was reopened afterwards ('Send More Coins'). | 0/O | `artifacts.page_visits` |

## 3. How to read what you find

| Kind | Subject | Statement | Tier/Basis | From |
|---|---|---|---|---|
| Identifier | `deposit_address` | Deposit address; display only; `^<btc_address>$`; Fresh service-controlled address per order (P2SH in both samples), printed on the order page with a QR code and in the letter; the service assigns no order number ('We do not attribute ID tracking numbers to your orders') and the FAQ tells the user to monitor this address on a block explorer | 0/O | `order_model.identifiers.deposit_address` |
| Receipt labels | Letter of Guarantee | `MixTum has generated the address` Deposit address; `Cleansed coins will be sent to the forwarding address` Destination address; `Anonymized coins will be sent to the destination address` Destination address; `the change will be sent to the address` Destination address; `valid for 168 hours from` Order time; `starting from` Order time; `Mixing mode:` Mixing mode; `Operation mode:` Mixing mode | 0/O | `receipts.letter_of_guarantee.field_map` |
| Signing identity | Letter of Guarantee | `D3B280956F0E7CAF` (PGP) | 0/O | `receipts.letter_of_guarantee.signature` |
| Caveat | Visits to the order form and order page | The urls row keeps the title of the last visit only: 'Created New Order \| MixTum.io' when the order page was the last visit of that URL, 'Create New Order \| MixTum.io' when the form was reopened afterwards ('Send More Coins'). | 0/O | `artifacts.page_visits.caveat` |
| Caveat | Session restore navigation entries with the order form POST body | Chrome 156 also writes a Sessions_Encrypted folder; if later versions stop writing plaintext session files, the POST bodies may no longer be readable from Sessions/. | 0/O | `artifacts.session_restore_state.caveat` |
| Caveat | Cloudflare Turnstile state partitioned for the service site | Cloudflare code shared by all sites behind Cloudflare; only the partition key names mixtum.io. | 0/O | `artifacts.turnstile_local_storage.caveat` |
| Fact row notes | Order ID | The service assigns no order identifier ('We do not attribute ID tracking numbers to your orders'); the deposit address is the only per-order value. | 0/O | `fact_coverage.order_id.notes` |
| Fact row notes | Deposit TXID | Tier-1 fact; the service shows no status, so even a funded order would expose it only on-chain. best_persistence is provisional. | 0/U | `fact_coverage.deposit_txid.notes` |
| Fact row notes | Payout TXID | Tier-1 fact; best_persistence is provisional. | 0/U | `fact_coverage.payout_txid.notes` |
| Fact row notes | Amounts | At tier 0 this is the payment amount requested in the amount mode (forward_amount) and the deposit window the order page computes from it; deposit and payout amounts are tier-1. In this case the requested amount reached no disk source. | 0/O | `fact_coverage.amounts.notes` |
| Fact row notes | Fee and delay settings | The user chooses neither fee nor delay; the service sets both at random within published bounds, and the letter prints only the bounds (service constants). | 0/O | `fact_coverage.fee_and_delay.notes` |
| Fact row notes | Session ID | The service keeps no session: the order is created and shown in one POST response and never referenced again. | 0/O | `fact_coverage.session_id.notes` |
| Fact row notes | Client IP address | Unlike a DDoS-Guard front, Cloudflare exposes nothing of the client's address to the browser; a search needs the IP from another source (notes.yaml could record the VM's public address). | 0/O | `fact_coverage.client_ip.notes` |
| Fact row notes | User identifier | Account-less and code-less: 'There is no need in using mixer-codes' (home page). | 0/O | `fact_coverage.user_identifier.notes` |
| Fact row notes | Status progression | The service shows no order status at any stage (status.mechanism none). | 0/O | `fact_coverage.status_progression.notes` |
| Operator statements on retention (compare) |  | None. All info about an order is deleted upon its completion (or when the offer expires). The only remaining trace of our work are the letters of guarantee we give you. | 0/C | `retention.stated_policy[0]` |
| Operator statements on retention (compare) |  | We neither require registration nor store logs. Once the mixing is done and transaction confirmed, the data on processed transactions is deleted. Following up to 7 days during which we expect to receive your deposit, the data also gets erased. | 0/C | `retention.stated_policy[1]` |
| Operator statements on retention (compare) |  | They remain valid for 7 days. | 0/C | `retention.stated_policy[2]` |

## 4. Absences that are expected (do not read them as deletion)

| Source | Finding (why absent) | Facts affected (cell detail) | Implication | Tier/Basis | From |
|---|---|---|---|---|---|
| History | No visited URL carries a deposit address, destination address, amount or the letter; the visit rows give only the mode (query parameter), the page title and the time: Form and order page share fixed paths; the letter is a Blob download; Cloudflare challenge redirects add __cf_chl_tk tokens, not order data | Deposit address: order pages live at /en/mix?mode=<mode>; no URL carries it; Destination address: no URL carries it; Letter of Guarantee: a Blob download leaves a download row, not a visit; Amounts: no URL carries it |  | 0/O | `negative_findings[5]` |
| Downloads | The download row carries no deposit address, destination address or amount; it gives the letter's file name, the mode and the time: Fixed file name and a blob: URL | Deposit address: blob URL and a fixed file name; Destination address: blob URL and a fixed file name; Amounts: blob URL and a fixed file name |  | 0/O | `negative_findings[6]` |
| Cookies | No application cookie at all; the only row for the host is Cloudflare's cf_clearance: The service sets no Set-Cookie header; cf_clearance is set by the challenge platform | Deposit address: the service sets no cookie; Destination address: the service sets no cookie; Amounts: the service sets no cookie; Mixing mode: the service sets no cookie; Session ID: no application session; the only cookie is the CDN's cf_clearance; Client IP address: no cookie carries it; cf_clearance is opaque |  | 0/O | `negative_findings[7]` |
| Web Storage / IndexedDB | Local Storage: Not written for the service origin: Page scripts make no Web Storage calls | Deposit address: page scripts make no storage calls; Destination address: page scripts make no storage calls; Letter of Guarantee: page scripts make no storage calls; Amounts: page scripts make no storage calls; Mixing mode: page scripts make no storage calls; Order time: page scripts make no storage calls | The only records naming the host are Cloudflare Turnstile entries under the challenges.cloudflare.com origin, partitioned for mixtum.io (artifact turnstile_local_storage) | 0/O | `negative_findings[0]` |
| Web Storage / IndexedDB | Session Storage: Not written for the service origin: Page scripts make no Web Storage calls; no Session Storage file mentions the host | Deposit address: page scripts make no storage calls; Destination address: page scripts make no storage calls; Letter of Guarantee: page scripts make no storage calls; Amounts: page scripts make no storage calls; Mixing mode: page scripts make no storage calls; Order time: page scripts make no storage calls |  | 0/O | `negative_findings[1]` |
| Web Storage / IndexedDB | IndexedDB: Not written for the service origin: Page scripts make no IndexedDB calls; the profile has no IndexedDB folder | Deposit address: page scripts make no storage calls; Destination address: page scripts make no storage calls; Letter of Guarantee: page scripts make no storage calls; Amounts: page scripts make no storage calls; Mixing mode: page scripts make no storage calls; Order time: page scripts make no storage calls |  | 0/O | `negative_findings[2]` |
| Autofill | No row for the typed destination, change address or amount (the autofill table is empty): Both order forms carry autocomplete=off, for which Chrome saves no form history | Destination address: the forms carry autocomplete=off, and no row was saved for the typed addresses; Amounts: autocomplete=off on the form; no row for the typed amount; Order time: no row is saved for the autocomplete=off forms |  | 0/O | `negative_findings[8]` |
| Autofill |  | Deposit address: displayed, never typed; Mixing mode: the mode is a hidden level field and a query parameter, never typed |  | 0/O | `fact_coverage.deposit_address.cells.autofill` |
| HTTP cache | Letter never fetched as a resource: The page script builds the letter as a client-side Blob from a hidden field; no request is made |  |  | 0/O | `negative_findings[3]` |
| HTTP cache | absent, no design reason: No order page in the cache: Inferred: the order page is the response to a form POST, which Chrome normally does not reuse; no Cache-Control header explains the absence |  |  | 0/O | `negative_findings[4]` |
| Session restore | absent, no design reason: Deposit address and letter text absent: Session restore keeps navigation entries and POST bodies; the deposit address and the hidden letter field are page content |  |  | 0/O | `negative_findings[9]` |
| Session restore | absent, no design reason: Amount-mode order absent: no forward_amount, destination or change address: The submission was intercepted by the Cloudflare challenge and re-posted with the challenge token as the only body field; only that re-post is in the navigation entry |  | An unchallenged amount-mode submission would keep forward_amount in the POST body, as the mix-mode submission kept forward_addr; not tested | 0/O | `negative_findings[10]` |

## 5. Beyond the disk

| Kind | Subject | Statement | Tier/Basis | From |
|---|---|---|---|---|
| Retention claim |  | None. All info about an order is deleted upon its completion (or when the offer expires). The only remaining trace of our work are the letters of guarantee we give you. | 0/C | `retention.stated_policy[0]` |
| Retention claim |  | We neither require registration nor store logs. Once the mixing is done and transaction confirmed, the data on processed transactions is deleted. Following up to 7 days during which we expect to receive your deposit, the data also gets erased. | 0/C | `retention.stated_policy[1]` |
| Retention claim |  | They remain valid for 7 days. | 0/C | `retention.stated_policy[2]` |
| Retention observed |  | About 16 hours after the capture every replayed request, including those carrying the recorded cf_clearance cookie, was answered by Cloudflare's challenge page; the service was not reached, so whether it still held the orders is unknown; cites: mt-replay (2026-10-30) | 0/O | `retention.observed[0]` |
| Consistency |  | untested: No request reached the origin on replay, and the service offers no lookup that could show whether an order record exists; the 7-day validity can only be tested by a deposit or by re-submitting a destination address and comparing deposit addresses, which was not done. | 0/I | `retention.consistency` |
| Receipt signature | Letter of Guarantee | scheme: PGP (Signature packet: version 4, type 0x01 (canonical text), RSA, SHA1, issuer key id D3B280956F0E7CAF, which is the tail of the fingerprint the site publishes (B8A5 CFCA F63F F2D8 384A 6B12 D3B2 8095 6F0E 7CAF) and links to /pgp-key.txt; the fingerprint printed inside the letter is a different key. The signature's own creation time equals the capture clock (UTC) while the printed 'GMT' time is two hours later: the server prints local time labelled GMT. The FAQ tells users to verify with Gpg4win or the 'PGP Checker' at bitlist.co.); `D3B280956F0E7CAF`; verification: Investigator task: the signature should be verified against the published key (/pgp-key.txt) and the identity it names. | 0/O | `receipts.letter_of_guarantee.signature` |

## 6. What this profile does not cover

| Limit | Detail | From |
|---|---|---|
| Tiers not run | 1 |  |
| Facts not tested in any source | Deposit TXID, Payout TXID |  |
| Sources not tested for any fact | none |  |
| Values not yet established | Not stated separately for the trial. | `modes[2].delay_options` |
| Values not yet established | Investigator task: the signature should be verified against the published key (/pgp-key.txt) and the identity it names. | `receipts[0].signature.verification` |
| Values not yet established | A user-side file, but the replay never reached the service, so nothing about server-side purging was observed. | `receipts[0].evidentiary_value.survives_server_purge` |
| Values not yet established | tier-1 fact; no deposit was made | `fact_coverage[4].attr` |
| Values not yet established | tier-1 fact; no payout was made | `fact_coverage[5].attr` |
| Entry status | reviewed |  |
| Disk evidence conditions | Windows 10, Chrome 156; Chrome closed normally; VM shut down normally before acquisition. The profile also holds the analyst's rehearsal of the same procedure on the evening before and the morning of the capture, without the proxy: visits, two earlier letter downloads (test mode and mix mode) in the download rows, and one earlier mix-mode POST body in session restore; the Downloads folder holds the capture's two letters. The analyst viewed the capture in the mitmproxy web interface inside the same profile; its History rows and cache entries (127.0.0.1:8081) are instrumentation and were excluded from every disk claim. | `observations.mt-disk` |

