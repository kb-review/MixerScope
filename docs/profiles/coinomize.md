# Coinomize: Investigator profile

**Scope of this profile.** entry status: *reviewed*; tiers: 0; valid: 2026-10 to 2026-10; environment: Windows 10, Chrome 155; acquisition conditions: Chrome closed normally; VM shut down normally before acquisition.

Tier/Basis: the number is the collection tier, the letter the evidence basis (O observed, I inferred, C claimed, U unknown). Every row names the entry field it comes from.

## 1. Was this service used? (search terms, strongest first)

| Search for | Kind | Tier/Basis | From |
|---|---|---|---|
| `coinomize.biz` | domain | 0/O | `indicators[0]` |
| `coino2q64k4fg3lkjsnhjeydzwykw22a56u5nf2rdfzkjuy3jbwvypqd.onion` | text string | 0/C | `indicators[3]` |
| `1CrywjDEzzpEMxdWzCDgtmZ3Tr57XrnANV` | text string | 0/O | `indicators[4]` |
| `coinomize.co` | domain | 0/C | `indicators[1]` |
| `coinomize.is` | domain | 0/C | `indicators[2]` |
| `THIS LETTER FROM coinomize\.biz` | text string | 0/O | `indicators[5]` |
| `Hereby we confirm that coinomize\.biz or coinomize\.co` | text string | 0/O | `indicators[6]` |
| `^Coinomize\.biz_Letter_<order_id>\.txt$` | file name | 0/O | `indicators[7]` |
| `^/order/letter/download/<order_id>$` | URL path | 0/O | `indicators[8]` |
| `output_address_1=<btc_address>&service_fee=<percent>&delay=<int>&csrf=` | text string | 0/O | `indicators[9]` |
| `ordernumb=<order_id>&csrf=` | text string | 0/O | `indicators[10]` |
| `Your Coinomize Code:` | text string | 0/O | `indicators[11]` |
| `Browser session expired - Coinomize` | text string | 0/O | `indicators[14]` |
| `^/(start-mixing\|create-order\|check-order\|status-order\|order-expired\|exist-error)$` | URL path | 0/O | `indicators[12]` |
| `^/captcddos` | URL path | 0/O | `indicators[13]` |
| `^PHPSESSID$` | cookie name (weak: shared with unrelated sites) | 0/O | `indicators[15]` |
| `^__ddg(1\|8\|9\|10)_$` | cookie name (weak: shared with unrelated sites) | 0/O | `indicators[16]` |
| `^server:\s*ddos-guard$` | response header (weak: shared with unrelated sites) | 0/O | `indicators[17]` |

| Domain | Role | Tier/Basis | From |
|---|---|---|---|
| `coinomize.biz` | canonical | 0/O | `identity.domains[0]` |
| `coinomize.co` | alias | 0/C | `identity.domains[1]` |
| `coinomize.is` | alias | 0/C | `identity.domains[2]` |
| `coino2q64k4fg3lkjsnhjeydzwykw22a56u5nf2rdfzkjuy3jbwvypqd.onion` | onion | 0/C | `identity.domains[3]` |
| `coinomize.bz` | suspected clone: a clone, not this service | 0/C | `identity.domains[4]` |
| `coinomize.cc` | suspected clone: a clone, not this service | 0/C | `identity.domains[5]` |
| `coinomize.net` | suspected clone: a clone, not this service | 0/C | `identity.domains[6]` |
| `coinomqrds5ti77r.onion` | suspected clone: a clone, not this service | 0/C | `identity.domains[7]` |

## 2. Where each fact is on the disk

| Facts (where in the record) | Location | Field | Recovery | Caveat | Tier/Basis | From |
|---|---|---|---|---|---|---|
| **Deposit address**: letter body; **Destination address**: letter body; **Order ID**: letter file name and body; **Letter of Guarantee**: the letter file; **Fee and delay settings**: letter body (fee percentage and delay); **Order time**: 'Your Order created on' in the letter body; file timestamps | File system | `<Downloads>/Coinomize.biz_Letter_<order_id>.txt` | User's Downloads folder; the file name carries the order number, the body the deposit and destination addresses, the fee percentage, the delay, the creation time and the service signature. Search unallocated space for the header line and the signing address. |  | 0/O | `artifacts.letter_file` |
| **Destination address**: output_address_1 rows, including an address from a rejected submission; **Order time**: date_created of the output_address_1 row (submission time) | Autofill | `Web Data: autofill rows with name = output_address_1` | Chrome Web Data DB, autofill table, field name output_address_1 (output_address_2.. for further addresses): every address the user typed into the form, including one from a rejected submission; date_created is the submission time. | Autofill keeps every address typed into the form, including addresses from submissions the service rejected (it refuses a destination already in an open order); confirm against the letter or the session-restore POST body. | 0/O | `artifacts.destination_autofill` |
| **Destination address**: create-order POST body and form field state; **Order ID**: status-lookup POST body; **Fee and delay settings**: service_fee and delay in the create-order POST body | Session restore | `Sessions/Session_<int> and Sessions/Tabs_<int> (SNSS)` | The navigation entries for the form POSTs keep their bodies as ASCII (coinocode=..&output_address_1=<btc_address>&service_fee=<percent>&delay=<int>&csrf=..&captcha=..&submit=Create+Order and ordernumb=<order_id>&csrf=..) and the form field state keeps the typed destination address in UTF-16; both the Session and the Tabs files hold them, in two generations. |  | 0/O | `artifacts.session_restore_state` |
| **Order ID**: letter file name and download URL; **Letter of Guarantee**: download row of the letter; **Order time**: letter download start time (follows creation by a user action) | Downloads | `History: downloads.target_path, downloads_url_chains.url (https://coinomize.biz/order/letter/download/<order_id>)` | Chrome History DB, downloads and downloads_url_chains tables: the target path and the server URL both carry the order number; start_time records the download, which follows order creation by a user action. The Download Service store (shared_proto_db) holds the same URL. |  | 0/O | `artifacts.letter_download_record` |
| **Order ID**: ordernumb row, if the user looked the order up | Autofill | `Web Data: autofill row with name = ordernumb` | Chrome Web Data DB, autofill table, field name ordernumb: the order number typed into the status form; present only if the user looked the order up. |  | 0/O | `artifacts.order_id_autofill` |
| **Order time**: visit time of /create-order, one second after the server's creation time | History | `History: urls.url and visits.visit_time for /start-mixing, /create-order, /order-expired, /check-order, /status-order` | Chrome History DB: the visit to /create-order is recorded one second after the creation time the server printed; the /check-order and /status-order visits date the status lookup. No URL carries an order value; the pages are at fixed paths and the state is server-side. |  | 0/O | `artifacts.page_visits` |
| **Client IP address**: __ddg9_ row, value encrypted | Cookies | `Network/Cookies: cookies row host_key .coinomize.biz, name __ddg9_` | Chrome Cookies DB; the value is the client's public IPv4 address, encrypted at rest with the profile's OS-bound key (decryptable with the user's Windows credentials). Creation time dates the first visit. |  | 0/O | `artifacts.client_ip_cookie_row` |

## 3. How to read what you find

| Kind | Subject | Statement | Tier/Basis | From |
|---|---|---|---|---|
| Identifier | `order_number` | Order ID; status lookup key; `^[0-9a-f]{20}$`; 20 lowercase hexadecimal characters assigned by the server at order creation; one sample, no decodable timestamp | 0/O | `order_model.identifiers.order_number` |
| Identifier | `deposit_address` | Deposit address; display only; `^<btc_address>$`; Fresh service-controlled address per order (P2PKH in the sample), displayed on the order and status pages and printed in the letter; not used as a lookup key | 0/O | `order_model.identifiers.deposit_address` |
| Identifier | `coinomize_code` | User identifier; cross-order user key; `^[A-Za-z0-9]{8}$`; 8 alphanumeric characters issued on the first order ('Your Coinomize Code' on the order page) and meant to be entered in the coinocode field of every later order so that the user never receives their own earlier coins; links a user's orders on the server | 0/O | `order_model.identifiers.coinomize_code` |
| Receipt labels | Letter of Guarantee | `has generated the following Bitcoin address:` Deposit address; `to the following address(es):` Destination address; `after an delay of` Fee and delay settings; `Your choosen fee is` Fee and delay settings; `Your Order created on` Order time; `Your Order Number is:` Order ID | 0/O | `receipts.letter_of_guarantee.field_map` |
| Signing identity | Letter of Guarantee | `1CrywjDEzzpEMxdWzCDgtmZ3Tr57XrnANV` (Bitcoin signed message) | 0/O | `receipts.letter_of_guarantee.signature` |
| Caveat | Destination address in autofill | Autofill keeps every address typed into the form, including addresses from submissions the service rejected (it refuses a destination already in an open order); confirm against the letter or the session-restore POST body. | 0/O | `artifacts.destination_autofill.caveat` |
| Fact row notes | Deposit TXID | Tier-1 fact; best_persistence is provisional until a funded order is run. | 0/U | `fact_coverage.deposit_txid.notes` |
| Fact row notes | Payout TXID | Tier-1 fact; best_persistence is provisional until a funded order is run. | 0/U | `fact_coverage.payout_txid.notes` |
| Fact row notes | Amounts | Tier-1 fact; the order page and letter print only the service minimum and the fixed per-address fee, which are service constants. best_persistence is provisional until a funded order is run. | 0/U | `fact_coverage.amounts.notes` |
| Fact row notes | Mixing mode | Single mixing mode for BTC; the '100% clean coins' option is a fee-and-delay preset (5%, 900 min), not a mode. ETH and XMR are shown as coming soon. | 0/O | `fact_coverage.mix_mode.notes` |
| Fact row notes | Session ID | The session id reaches disk only if Chrome is killed or set to continue where it left off; with a normal exit it is network-only. | 0/O | `fact_coverage.session_id.notes` |
| Fact row notes | User identifier | Inferred: the code field is a named text field like output_address_1, which reaches autofill and session restore; not tested. | 0/O | `fact_coverage.user_identifier.notes` |
| Fact row notes | Status progression | Tier-1 fact; best_persistence is provisional until a funded order is run. | 0/O | `fact_coverage.status_progression.notes` |
| Operator statements on retention (compare) |  | We do not store any logs of your transaction, not even your IP or Bitcoin addresses. We delete all orders after 24-72 hours (Depending on choosen delay time.), but you can also delete it by yourself. | 0/C | `retention.stated_policy[0]` |
| Operator statements on retention (compare) |  | an auto-deletion occurs after 72 hours removing the records permanently | 0/C | `retention.stated_policy[1]` |
| Operator statements on retention (compare) |  | Your order is valid for 3 days and will be deleted after this time! | 0/C | `retention.stated_policy[2]` |
| Operator statements on retention (compare) |  | Your order is valid for 24 hours and will be deleted if no coins are received! | 0/C | `retention.stated_policy[3]` |
| Operator statements on retention (compare) |  | The data will be deleted after 3 days. | 0/C | `retention.stated_policy[4]` |

## 4. Absences that are expected (do not read them as deletion)

| Source | Finding (why absent) | Facts affected (cell detail) | Implication | Tier/Basis | From |
|---|---|---|---|---|---|
| History | No visited URL carries an order value (deposit address, destination address, order number, code, fee or delay); only the visit times remain: Order and status pages live at fixed paths with the state in the PHP session; the only URL with the order number is the letter download, which Chrome records as a download rather than a visit | Deposit address: no URL carries it; Destination address: no URL carries it; Order ID: order and status pages are at fixed paths; the letter URL is recorded as a download, not a visit; Letter of Guarantee: recorded as a download, not a visit; Fee and delay settings: no URL carries it; Session ID; User identifier: no URL carries it |  | 0/O | `negative_findings[4]` |
| Downloads | The download record carries no order value other than the order number (plus the download time): The letter URL and file name contain the order number and nothing else | Deposit address: the letter URL carries only the order number; Destination address: the letter URL carries only the order number; Fee and delay settings: the letter URL carries only the order number; Session ID; User identifier: not in the letter URL |  | 0/O | `negative_findings[5]` |
| HTTP cache | Order page, status page, order form, expiry page and letter absent; the cache holds the home page, the /exist-error page and static assets: Served with Cache-Control: no-store, no-cache, must-revalidate; the cached home page carries only the service's signing/donation address | Deposit address: order page, status page and letter are no-store; Destination address: order page, status page and letter are no-store; Order ID: order page, status page and letter are no-store; Letter of Guarantee: served no-store as an attachment; Fee and delay settings: order page, status page and letter are no-store; Order time: order page, status page and letter are no-store; Session ID; User identifier: shown only on the no-store order page; Status progression: order and status pages are no-store |  | 0/O | `negative_findings[3]` |
| Cookies | No cookie carries an order value: The Set-Cookie headers in the capture carry the PHP session id, DDoS-Guard tokens and the client IP only | Deposit address: no cookie carries an order value; Destination address: no cookie carries an order value; Order ID: no cookie carries an order value; Fee and delay settings: no cookie carries an order value; User identifier: no cookie carries it |  | 0/O | `negative_findings[7]` |
| Web Storage / IndexedDB | Local Storage: Not written for the service origin: Page scripts make no Web Storage calls; no Local Storage file mentions the host | Deposit address; Destination address; Order ID; Letter of Guarantee; Fee and delay settings; Order time; Session ID; Client IP address; User identifier; Status progression |  | 0/O | `negative_findings[0]` |
| Web Storage / IndexedDB | Session Storage: Not written for the service origin: Page scripts make no Web Storage calls; no Session Storage file mentions the host | Deposit address; Destination address; Order ID; Letter of Guarantee; Fee and delay settings; Order time; Session ID; Client IP address; User identifier; Status progression |  | 0/O | `negative_findings[1]` |
| Web Storage / IndexedDB | IndexedDB: Not written for the service origin: Page scripts make no IndexedDB calls; no IndexedDB file mentions the host | Deposit address; Destination address; Order ID; Letter of Guarantee; Fee and delay settings; Order time; Session ID; Client IP address; User identifier; Status progression |  | 0/O | `negative_findings[2]` |
| Autofill | Deposit address absent: Displayed by the service, never typed | Deposit address: displayed, never typed |  | 0/O | `negative_findings[8]` |
| Autofill | Fee and delay absent: Both are range inputs on the form; Chrome autofill saves text fields only | Fee and delay settings: fee and delay are range inputs, which autofill does not save |  | 0/O | `negative_findings[9]` |
| Cookies | No PHPSESSID row: Session cookie without Expires or Max-Age; Chrome does not persist it on a normal exit | Session ID: PHPSESSID is a session cookie without Expires; not written to the Cookies DB on normal exit |  | 0/O | `negative_findings[6]` |
| Session restore | absent, no design reason: Deposit address, Coinomize Code and session id absent: Session restore keeps navigation entries, POST bodies and typed form state; the deposit address and the code are server-rendered page content, the session id is a cookie |  |  | 0/O | `negative_findings[10]` |

## 5. Beyond the disk

| Kind | Subject | Statement | Tier/Basis | From |
|---|---|---|---|---|
| Lookup endpoint | POST `^/status-order$` | looked up by: Order ID; ownership check: no; gate: session, CSRF | 0/O | `endpoints.status_lookup` |
| Replay result | `order_expired` | Original request, live session: Served, but without the order number: the session no longer holds the order (accepted); cites: cz-replay (2026-10-21) | 0/O | `endpoints.order_expired.replay_results[0]` |
| Replay result | `status_lookup` | Original request, live session: The stale CSRF token is refused (redirect to /wrong-token), yet the response body carries the live record three days after creation and after the 'valid until' time the service itself prints: order number, creation time, fee, delay, destination and deposit addresses and the current blockchain-fee tip (live); cites: cz-replay (2026-10-21) | 0/O | `endpoints.status_lookup.replay_results[0]` |
| Replay result | `status_page` | Original request, live session: Answered with the record of the order the preceding replayed lookup had placed in the session; the delay and minimum shown are session defaults ('Instant', 0 BTC), not the order's values, and the meta refresh sends a browser back to the form (live); cites: cz-replay (2026-10-21) | 0/O | `endpoints.status_page.replay_results[0]` |
| Retention claim |  | We do not store any logs of your transaction, not even your IP or Bitcoin addresses. We delete all orders after 24-72 hours (Depending on choosen delay time.), but you can also delete it by yourself. | 0/C | `retention.stated_policy[0]` |
| Retention claim |  | an auto-deletion occurs after 72 hours removing the records permanently | 0/C | `retention.stated_policy[1]` |
| Retention claim |  | Your order is valid for 3 days and will be deleted after this time! | 0/C | `retention.stated_policy[2]` |
| Retention claim |  | Your order is valid for 24 hours and will be deleted if no coins are received! | 0/C | `retention.stated_policy[3]` |
| Retention claim |  | The data will be deleted after 3 days. | 0/C | `retention.stated_policy[4]` |
| Retention observed |  | About 78 hours after creation, past the 'valid until' time the service prints, the lookup by order number still returned the full record of the unfunded order (number, creation time, fee, delay, destination and deposit addresses, waiting state); cites: cz-replay (2026-10-21) | 0/O | `retention.observed[0]` |
| Retention observed |  | The recorded PHP session no longer resolved to the order: the order page redirected to /mix-error and the letter URL to the home page; cites: cz-replay (2026-10-21) | 0/O | `retention.observed[1]` |
| Consistency |  | contradicted: The unfunded order was still served about 78 hours after creation, past the 24-hour (letter) and 3-day (order page) deadlines. One replay; deletion may be batched or delayed rather than absent. A later replay would settle it. The 'no logs' claim is untested. | 0/I | `retention.consistency` |
| Receipt signature | Letter of Guarantee | scheme: Bitcoin signed message (Bitcoin signed-message block format; the FAQ tells users to verify it in Electrum against the signing address.); `1CrywjDEzzpEMxdWzCDgtmZ3Tr57XrnANV`; verification: Investigator task: the signature over the message block should be verified against the signing address and the published identity. | 0/O | `receipts.letter_of_guarantee.signature` |

## 6. What this profile does not cover

| Limit | Detail | From |
|---|---|---|
| Tiers not run | 1 |  |
| Facts not tested in any source | Deposit TXID, Payout TXID, Amounts |  |
| Sources not tested for any fact | none |  |
| Values not yet established | No maximum stated; the FAQ only mentions several nodes and cold wallets with different balances. | `modes[0].limits.max` |
| Values not yet established | Investigator task: the signature over the message block should be verified against the signing address and the published identity. | `receipts[0].signature.verification` |
| Values not yet established | tier-1 fact; no deposit was made | `fact_coverage[4].attr` |
| Values not yet established | tier-1 fact; no payout was made | `fact_coverage[5].attr` |
| Values not yet established | tier-1 fact; no deposit was made | `fact_coverage[6].attr` |
| Entry status | reviewed |  |
| Disk evidence conditions | Windows 10, Chrome 155; Chrome closed normally; VM shut down normally before acquisition | `observations.cz-disk` |

