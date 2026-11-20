# Mixero: Investigator profile

**Scope of this profile.** entry status: *reviewed*; tiers: 0, 1; valid: 2026-07 to 2026-10; environment: Windows 10, Chrome 150; acquisition conditions: Chrome closed normally; VM shut down normally before acquisition. Acquired after the tier-1 run; covers the tier-0 artifacts as well.

Tier/Basis: the number is the collection tier, the letter the evidence basis (O observed, I inferred, C claimed, U unknown). Every row names the entry field it comes from.

## 1. Was this service used? (search terms, strongest first)

| Search for | Kind | Tier/Basis | From |
|---|---|---|---|
| `mixero.io` | domain | 0/O | `indicators[0]` |
| `mixero.co` | domain | 0/O | `indicators[1]` |
| `1HsM2JbyKnqwcYvEm1kLMNwJtqb6uxSczd` | text string | 0/O | `indicators[2]` |
| `mixeroyubx5g5yxaucsxcd767vn2lnujuuz2dh53quwabukhrok2ekid.onion` | text string | 0/O | `indicators[3]` |
| `^/Home/check_transaction$` | URL path | 0/O | `indicators[4]` |
| `^/Home/set_transaction_coinjoin$` | URL path | 0/O | `indicators[5]` |
| `Mixero confirms that the following address` | text string | 0/O | `indicators[8]` |
| `^/scripts/letter\.php` | URL path | 0/O | `indicators[6]` |
| `^/(mix\|invoice)_coinjoin$` | URL path | 0/O | `indicators[7]` |
| `-----START ADDRESS FOR SENDING FUNDS-----` | text string | 0/O | `indicators[9]` |
| `Transaction has been completed with TXID:` | text string | 1/O | `indicators[10]` |
| `We have detected a transaction\. Waiting for 1 confirmation` | text string | 1/O | `indicators[11]` |
| `^Letter_<order_id>\.txt$` | file name | 0/O | `indicators[14]` |
| `we just started mixing your funds` | text string | 1/O | `indicators[12]` |
| `Awaiting an incoming transaction` | text string | 0/O | `indicators[13]` |
| `^ci_session$` | cookie name (weak: shared with unrelated sites) | 0/O | `indicators[15]` |
| `^__ddg(1\|8\|9\|10)_$` | cookie name (weak: shared with unrelated sites) | 0/O | `indicators[16]` |
| `^server:\s*ddos-guard$` | response header (weak: shared with unrelated sites) | 0/O | `indicators[17]` |

| Domain | Role | Tier/Basis | From |
|---|---|---|---|
| `mixero.io` | canonical | 0/O | `identity.domains[0]` |
| `mixero.co` | assets / API | 0/O | `identity.domains[1]` |
| `mixero.org` | alias | 0/O | `identity.domains[2]` |
| `mixero.website` | alias | 0/O | `identity.domains[3]` |
| `mixeruni.com` | alias | 0/O | `identity.domains[4]` |
| `mixeroyubx5g5yxaucsxcd767vn2lnujuuz2dh53quwabukhrok2ekid.onion` | onion | 0/O | `identity.domains[5]` |

## 2. Where each fact is on the disk

| Facts (where in the record) | Location | Field | Recovery | Caveat | Tier/Basis | From |
|---|---|---|---|---|---|---|
| **Deposit address**: letter.php cache entry (address= in the key; letter body); **Destination address**: letter body in the letter.php cache entry; **Order ID**: letter.php cache entry (full ID in the key's session= value and in the body); **Letter of Guarantee**: letter body in the letter.php cache entry; **Fee and delay settings**: fee percentage in the cached letter body; the delay is not stated; **Mixing mode**: mode= parameter in the letter.php cache key; **Order time**: date block of the cached letter body (server time, +0300); creation time to the microsecond from the 13-hex prefix of the key's session= value | HTTP cache | `Cache/Cache_Data/data_* (block-file cache); key '1/0/_dk_https://mixero.co https://mixero.co https://mixero.co/scripts/letter.php?address=<btc_address>&session=session<order_id>&mode=<mix_mode>'` | Chrome HTTP cache, block-file format. The key, which has a partitioned-cache prefix, carries the deposit address, 'session' + the full order ID (whose first 13 hex digits are the creation time) and the mode; the gzip body is the letter text with the full order ID, the deposit and destination addresses, the fee percentage, the server-local date block and the 48-hour validity paragraph. Match the letter.php URL as a substring of the key. | The key is longer than the 160-byte key field of one 256-byte block, so the entry spans two blocks; a viewer that shows one block cuts the key after the 13-hex creation-time prefix, before the rest of the ID and the mode parameter. | 0/O | `artifacts.letter_cache_entry` |
| **Deposit address**: page state; **Destination address**: form state; **Order ID**: page state; **Deposit TXID** (1/O): explorer URL in navigation entries; **Mixing mode**: page URLs | Session restore | `Sessions/Session_<int>, Sessions/Tabs_<int> (SNSS)` | String carve of the SNSS files; form state and navigation entries (page URLs, the explorer URL) survive there |  | 0/O | `artifacts.session_restore_state` |
| **Deposit address**: letter body; **Destination address**: letter body; **Order ID**: file name and body; **Letter of Guarantee**: the letter file in Downloads; **Fee and delay settings**: fee percentage in the letter; the delay is not stated; **Order time**: letter date block; also derivable from the order ID (uniqid unix seconds) | File system | `<Downloads>/Letter_<order_id>.txt` | User's Downloads folder; the file name carries the order ID, the body the deposit and destination addresses, the fee percentage, the creation date and the service signature. Also search unallocated space for the body template. |  | 0/O | `artifacts.letter_file` |
| **Destination address**: destination_address-<int> | Autofill | `Web Data: autofill.name = destination_address-<int>` | Chrome Web Data autofill table, rows whose name matches destination_address-<int> | Which form (CoinJoin or Advanced) produced the entry is not pinned down. | 0/O | `artifacts.destination_autofill` |
| **Order ID**: file name; **Letter of Guarantee**: download record with file name and target path; **Order time**: download start time | Downloads | `History: downloads.target_path, downloads_url_chains.url (blob: URL)` | Chrome History DB, downloads table; target_path basename matches the file name pattern; start_time gives the download time; the URL chain is a blob: URL and the referrer is the invoice tab |  | 0/O | `artifacts.letter_download_record` |
| **Order ID**: orderId | Autofill | `Web Data: autofill.name = orderId` | Chrome Web Data autofill table, name = orderId (typed into the status lookup form) |  | 0/O | `artifacts.order_id_autofill` |
| **Deposit TXID**: explorer visit (user click) | History | `History: urls.url = https://mempool.space/tx/<txid_hex64>` | Chrome History; explorer URLs containing a 64-hex TXID; user-behaviour dependent |  | 1/O | `artifacts.explorer_visit` |
| **Mixing mode**: URL path (/mix_coinjoin, /invoice_coinjoin, /mix_advanced); **Order time**: visit times | History | `History: urls / visits` | Query urls/visits for the service host; the mode from the URL path (/mix_coinjoin, /invoice_coinjoin, /mix_advanced), the session time from visit_time; no order ID in any page URL |  | 0/O | `artifacts.page_visits` |
| **Order time**: cookie creation times; **Session ID**: ci_session row, value encrypted | Cookies | `Network/Cookies: cookies.name = ci_session` | Chrome Cookies DB; name, host and times in plaintext, latest value only and encrypted; creation and last-access times frame the session |  | 0/O | `artifacts.session_cookie_row` |
| **Client IP address**: __ddg9_ row, value encrypted | Cookies | `Network/Cookies: cookies.name = __ddg9_` | Chrome Cookies DB row; the value is the public IPv4 address the subject used, but Chrome stores cookie values encrypted at rest (DPAPI / OS key ring), so decryption with the profile's key is needed to read it | The row (name, host, times) was found with an encrypted value and no plaintext; the IP itself was not read from disk. | 0/O | `artifacts.client_ip_cookie_row` |

## 3. How to read what you find

| Kind | Subject | Statement | Tier/Basis | From |
|---|---|---|---|---|
| Identifier | `uniqid_order_id` | Order ID; record key; `^[0-9a-f]{14}\.\d+$`; PHP uniqid(prefix, true) with the literal prefix 'session' internally (session<13 hex><digit>.<8 digits>); the UI strips the prefix. The first 8 hex characters are the unix seconds of order creation, the next 5 the microseconds, then a decimal entropy suffix (one digit, a point, eight digits). The letter.php cache key carries 'session' + the full ID, so the creation time can be read from the cache key alone (its first 13 hex digits); the full ID is also in the cached letter body. | 0/O | `order_model.identifiers.uniqid_order_id` |
| Identifier | `deposit_address` | Deposit address; status lookup key; `^<btc_address>$`; Fresh service-controlled address per order; the operational lookup key for status (POST check_transaction keyed by bitcoin_address). | 0/O | `order_model.identifiers.deposit_address` |
| Receipt labels | Letter of Guarantee | `Mixero confirms that the following address` Deposit address; `in order to receive your funds to the following destination address:` Destination address; `The fees for this transaction are` Fee and delay settings; `Your Order ID is` Order ID; `-----START DATE-----` Order time; `-----START ADDRESS FOR SENDING FUNDS-----` Deposit address; `-----START DESTINATION ADDRESSES-----` Destination address | 0/O | `receipts.letter_of_guarantee.field_map` |
| Signing identity | Letter of Guarantee | `1HsM2JbyKnqwcYvEm1kLMNwJtqb6uxSczd` (Bitcoin signed message) | 0/I | `receipts.letter_of_guarantee.signature` |
| Caveat | Cached letter.php response | The key is longer than the 160-byte key field of one 256-byte block, so the entry spans two blocks; a viewer that shows one block cuts the key after the 13-hex creation-time prefix, before the rest of the ID and the mode parameter. | 0/O | `artifacts.letter_cache_entry.caveat` |
| Caveat | __ddg9_ cookie row (client IP) | The row (name, host, times) was found with an encrypted value and no plaintext; the IP itself was not read from disk. | 0/O | `artifacts.client_ip_cookie_row.caveat` |
| Caveat | Destination address in autofill | Which form (CoinJoin or Advanced) produced the entry is not pinned down. | 0/O | `artifacts.destination_autofill.caveat` |
| Fact row notes | User identifier | Account-less service: no cross-order user identifier exists. | 0/O | `fact_coverage.user_identifier.notes` |
| Operator statements on retention (compare) |  | Transaction details are kept only until the mix completes and is confirmed | 0/C | `retention.stated_policy[0]` |
| Operator statements on retention (compare) |  | No trace remains after the 24-hour session | 0/C | `retention.stated_policy[1]` |
| Operator statements on retention (compare) |  | The letter of guarantee must be submitted within 48 hours of payment if problems arise. Failure to comply will invalidate the letter per our Data Confidentiality policy. If a delay is set, the letter expires 48 hours after this delay. | 0/C | `retention.stated_policy[2]` |

## 4. Absences that are expected (do not read them as deletion)

| Source | Finding (why absent) | Facts affected (cell detail) | Implication | Tier/Basis | From |
|---|---|---|---|---|---|
| Web Storage / IndexedDB | Local Storage: Not written for the service origin: Page scripts make no Web Storage calls | Deposit address; Destination address; Order ID; Letter of Guarantee; Deposit TXID; Payout TXID; Amounts; Fee and delay settings; Mixing mode; Order time; Session ID; Client IP address; Status progression |  | 0/O | `negative_findings[0]` |
| Web Storage / IndexedDB | Session Storage: Not written for the service origin: Page scripts make no Web Storage calls | Deposit address; Destination address; Order ID; Letter of Guarantee; Deposit TXID; Payout TXID; Amounts; Fee and delay settings; Mixing mode; Order time; Session ID; Client IP address; Status progression |  | 0/O | `negative_findings[1]` |
| Web Storage / IndexedDB | IndexedDB: Not written for the service origin: Page scripts make no IndexedDB calls | Deposit address; Destination address; Order ID; Letter of Guarantee; Deposit TXID; Payout TXID; Amounts; Fee and delay settings; Mixing mode; Order time; Session ID; Client IP address; Status progression |  | 0/O | `negative_findings[2]` |
| Autofill | The deposit address is absent from autofill: Displayed by the service, never typed by the user | Deposit address: displayed, never typed |  | 0/O | `negative_findings[6]` |
| History | No page URL carries the order ID: The order ID travels only in POST bodies and in the script-fetched letter.php resource URL | Order ID: no page URL carries the order ID |  | 0/O | `negative_findings[4]` |
| HTTP cache | Invoice page and status responses absent: Served with Cache-Control: no-store | Deposit TXID: no-store status response; Payout TXID: no-store; Amounts; Status progression: no-store |  | 0/O | `negative_findings[3]` |
| History |  | Payout TXID: no page URL carries it; the completion response that shows it is no-store |  | 1/O | `fact_coverage.payout_txid.cells.history` |
| Network only | Request bodies (deposit and destination in POSTs) are not persisted by the browser: Chrome stores no request bodies |  | Form field state reaches disk through session restore and autofill instead | 0/O | `negative_findings[7]` |
| History | absent, no design reason: No letter.php URL in History: The receipt is not in History; the only History-database trace of the letter is the download row written when the user downloads it (downloads column, letter_download_record) |  |  | 0/O | `negative_findings[5]` |

## 5. Beyond the disk

| Kind | Subject | Statement | Tier/Basis | From |
|---|---|---|---|---|
| Lookup endpoint | POST `^/Home/check_transaction$` | looked up by: Deposit address; ownership check: no; gate: session, CSRF | 0/O | `endpoints.check_transaction` |
| Lookup endpoint | POST `^/Home/fetch_order$` | looked up by: Order ID; gate: session, CSRF, captcha | 0/O | `endpoints.fetch_order` |
| Replay result | `check_transaction` | Original request, live session: Completion record served while the order's session is live (live); cites: mx-flow (2026-07-22) | 1/O | `endpoints.check_transaction.replay_results[0]` |
| Replay result | `check_transaction` | Superseded session, own order key: Superseded session still accepted; the completion record is no longer served (purged), the order is reported as mixing (accepted); cites: mx-replay (2026-08) | 1/O | `endpoints.check_transaction.replay_results[1]` |
| Replay result | `check_transaction` | Valid session, another order's key: Key taken from the body; no ownership check (accepted); cites: mx-replay (2026-08) | 1/O | `endpoints.check_transaction.replay_results[3]` |
| Retention claim |  | Transaction details are kept only until the mix completes and is confirmed | 0/C | `retention.stated_policy[0]` |
| Retention claim |  | No trace remains after the 24-hour session | 0/C | `retention.stated_policy[1]` |
| Retention claim |  | The letter of guarantee must be submitted within 48 hours of payment if problems arise. Failure to comply will invalidate the letter per our Data Confidentiality policy. If a delay is set, the letter expires 48 hours after this delay. | 0/C | `retention.stated_policy[2]` |
| Retention observed |  | Completion record (payout TXID) no longer served about two weeks after completion; cites: mx-replay (2026-08) | 1/O | `retention.observed[0]` |
| Retention observed |  | Superseded session identifiers still accepted about two weeks later; deposit-address resolution still works; cites: mx-replay (2026-08) | 1/O | `retention.observed[1]` |
| Consistency |  | partially consistent: First claim consistent with the purge; second contradicted by the validity of old sessions. | 1/I | `retention.consistency` |
| Receipt signature | Letter of Guarantee | scheme: Bitcoin signed message (A base64 signature over the letter block, attributed to a Bitcoin address; verification of the exact message bytes not yet performed.); `1HsM2JbyKnqwcYvEm1kLMNwJtqb6uxSczd`; verification: Investigator task: the signature should be verified against the signing address and the published identity. | 0/I | `receipts.letter_of_guarantee.signature` |
| Blockchain | Deposit address | Recovered: deposit output | 0/O | `fact_coverage.deposit_address.cells.chain` |
| Blockchain | Destination address | Required to query: payout found only from a known destination | 0/O | `fact_coverage.destination_address.cells.chain` |
| Blockchain | Deposit TXID | Recovered | 1/O | `fact_coverage.deposit_txid.cells.chain` |
| Blockchain | Payout TXID | Recovered: from a known destination address (recovered on disk from the letter, autofill or session restore) | 1/O | `fact_coverage.payout_txid.cells.chain` |
| Blockchain | Amounts | Recovered: deposit output; the payout amount only from a known destination address | 1/O | `fact_coverage.amounts.cells.chain` |
| Blockchain | Fee and delay settings | Recovered: fee derivable as deposit minus payout | 0/O | `fact_coverage.fee_and_delay.cells.chain` |
| Blockchain | Mixing mode | Not found | 0/O | `fact_coverage.mix_mode.cells.chain` |

## 6. What this profile does not cover

| Limit | Detail | From |
|---|---|---|
| Tiers not run | none |  |
| Facts not tested in any source | none |  |
| Sources not tested for any fact | none |  |
| Values not yet established | Access model not tested without a session. | `endpoints[7].gate` |
| Values not yet established | Investigator task: the signature should be verified against the signing address and the published identity. | `receipts[0].signature.verification` |
| Entry status | reviewed |  |
| Disk evidence conditions | Windows 10, Chrome 150; Chrome closed normally; VM shut down normally before acquisition. Acquired after the tier-1 run; covers the tier-0 artifacts as well | `observations.mx-disk` |

