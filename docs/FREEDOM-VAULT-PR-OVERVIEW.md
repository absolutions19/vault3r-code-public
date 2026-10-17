# VAULT — the Freedom Browser pull request

What the data-vault feature adds to Freedom Browser, written for the
maintainers of [`solardev-xyz/freedom-browser`](https://github.com/solardev-xyz/freedom-browser)
deciding whether to take it on, and for whoever reviews it after them.

It lands as **five commits** on [`0x-noad/freedom-browser`](https://github.com/0x-noad/freedom-browser),
rebased onto upstream `main` at `52cd49bc`: the vendored engine and its
licensing records, the main-process host, the Data pane, the launcher, and the
docs. Each passes the full suite on its own. Last refreshed 2026-10-17.

---

## 1. What it is, in one paragraph

Every site gets its own encrypted key/value document in the user's vault,
reachable from the page as `window.vault`. The site declares which JSON Pointer
paths it wants and whether it needs to write; the user approves the partition
once; the data is sealed under a key derived from the wallet the browser already
has. A site may also publish part of its document under the reserved pointer
`/shared` and another site may be granted **read-only** access to that subtree —
approved by the user, per reader→owner pair. The wallet sidebar gains a **Data**
pane that manages all of it, and `freedom://dapps` lists the sites holding data.

Nothing is sent anywhere. There is no network path in the feature: storage is
local files under `userData`, the engine is in-process, and the launcher page
runs with `connect-src 'none'`.

## 2. The two repositories

| Repo | Role |
| --- | --- |
| `solardev-xyz/freedom-browser` | upstream. The PR target. |
| `0x-noad/freedom-browser` | this fork. Integration: host glue, IPC, the Data pane, the launcher, docs. |
| `vault3r-code-public` (separate, local) | the engine: crypto, grant arithmetic, document store, namespace derivation. TypeScript, vitest, 50+ tests for cross-partition reads alone. |

The engine is **vendored** into this repo as one generated file —
`src/main/vault/vendor/vault-bundle.js` (423 KB) plus two 2-line CommonJS shims
and a README. It is built in the engine repo
(`node tools/bundle-for-freedom.mjs <path-to-freedom-browser>`) and is lint-,
coverage- and hand-edit-exempt.

It is **MPL-2.0, the same license as Freedom**, so the bundle and the host glue
beside it mix without condition and nothing needs relicensing. Its banner
records the source repository, the exact revision it was built from (`+local`
when built over uncommitted work) and the libraries it inlines; the output is
deterministic, so rebuilding the same revision changes only that banner. It
inlines six MIT libraries — `@noble/{ciphers,curves,hashes}`, `@scure/base`,
`@scure/bip39` and `tldts` — attributed in `NOTICES`, recorded in
`LICENSE_AUDIT.md` and `licenses-audit.json`, and enforced by
`licenses-audit.test.js`, which now classifies this directory file by file.
Five of the six are already in Freedom's npm tree at the same versions; `tldts`
(the Public Suffix List) arrives only here, because Electron exposes no PSL API
and a "last two labels" check would make `attacker.co.uk` authoritative for
`victim.co.uk`.

## 3. Trust model

The one invariant everything else rests on:

> **The calling origin is never page-supplied.** It comes from
> `event.senderFrame.url` in the main process. A page cannot name another
> site's namespace, and cannot name itself as someone else.

From that:

- **Origin → namespace** is derived by the engine (`deriveOriginNamespace`),
  scheme included, with `*.localhost` keyed by port. `https://a.example` and
  `bzz://a.example` are two partitions.
- **Namespace → storage key** is `sha256(namespace)`; each partition gets its own
  HKDF subkey, and an anti-rollback manifest plus an owner fingerprint guards
  against swapped or replayed blobs.
- **Cross-origin reads** add no exception to the rule. The reader's identity
  still comes from its frame; the owner's comes from a stored grant the user
  approved. The page passes an owner *origin*, which the engine runs through the
  same derivation before it will touch anything — it cannot pass a namespace or
  a storage key.
- **Absent data reads as empty.** A path the owner never wrote, an owner with no
  partition, an owner the user declined and a pointer outside `/shared` are
  indistinguishable: every one answers `null`, with no error code. Anything else
  would be an existence oracle over the user's browsing history.

## 4. Why `/shared` and not a flag

The writer marks data as publishable **by where it stores it**. There is no
`shareable: true` field. Location cannot be mis-set, needs no new metadata, and
makes the reader's consent sheet honest without the owner having to be present.

One consequence had to be built deliberately: a write under `/shared` requires a
granted rule rooted at or below `/shared`. Without that gate, a site granted the
whole document (the empty pointer covers everything) could publish without
`/shared` ever appearing on its consent sheet, and "location is the mark" would
not be true.

## 5. What was added, file by file

**New, entirely ours** — 15 files, all additive:

```
src/main/vault/data-vault-manager.js        990  host glue: routing, consent, sessions, owner plane
src/main/vault/data-vault-permissions.js    350  the remembered-grant store (safeStorage-encrypted)
src/main/vault/data-vault-icon.js           258  site icon validation + monogram fallback
src/main/vault/register-data-vault.js       195  wiring + the no-wallet-window fallback prompt
src/main/vault/data-vault-keystore.js       176  key derivation from the identity vault
src/main/vault/data-vault-storage.js        125  sealed blobs under userData/vault-data/
src/main/vault/vault-provider-inject.js     106  the page-realm window.vault source
src/main/vault/vault-ipc-channels.js         60  every channel name in one place
src/main/vault/vendor/README.md              62  what the bundle is, and how to rebuild it
src/renderer/lib/wallet/vault-data.js       836  the Data pane (list, detail, consent sheet, banner)
src/renderer/styles/vault-data.css          405  pane styles, tokens only
src/renderer/pages/dapps.html               192  freedom://dapps launcher
src/renderer/pages/scripts/dapps.js         113  its tiles
docs/vault-for-site-authors.md              310  the site-author guide
types/freedom-vault.d.ts                    190  the page-facing types
+ 4 test files (2,089 lines) and one changelog fragment
```

17,617 lines added, 23 removed.

**Seams — existing files we touched.** The whole branch adds 17,374 lines and
*removes* 23, every one of which is a counter or label in an existing test, a
line extended rather than replaced, or the two guards below being widened:

| File | +/− | What it is |
| --- | --- | --- |
| `src/main/index.js` | +8 | register the vault at startup |
| `src/main/ipc-sender-policy.js` | +23 | tier entries for the new channels, with the reasoning |
| `src/main/preload.js` | +68 | the chrome-renderer `window.vaultData` bridge |
| `src/main/webview-preload.js` | +106 −1 | install `window.vault` at document start |
| `src/renderer/index.html` | +200 | the Data pane markup |
| `src/renderer/lib/wallet-ui.js` | +50 | wire the pane into the sidebar |
| `src/renderer/lib/navigation.js` | +5 | the `freedom://dapps` route |
| `src/renderer/lib/dapp-provider.js` | +2 −1 | refresh the vault banner on tab switch |
| `src/renderer/styles.css` | +1 | one `@import` |
| `src/shared/internal-pages.json` | +1 | the launcher's entry |
| `eslint.config.js` | +1 | ignore the generated vendor dir |
| `README.md`, `docs/features.md` | +4 | two feature lines and a table row |
| `NOTICES`, `LICENSE_AUDIT.md`, `licenses-audit.json` | +93 | the vendored engine, attributed and recorded |
| `licenses-audit.test.js` | +45 −10 | classify the new vendor dir, and widen the bundle sweep to `[.-]bundle.js` |
| `jest.config.js` | +9 −1 | exclude the generated bundle from coverage |
| 3 existing test files | +43 −10 | call counts and a regex generalised |

No existing behaviour is changed. Remove the `src/main/vault/` directory, the
`registerDataVault()` call and the seams above and the browser is byte-identical
in behaviour to upstream.

## 6. IPC surface

One site-facing channel, and it already existed as a tier:

- `vault:provider-request` — **PUBLIC** tier. Every page method (`connect`,
  `get`, `set`, `patch`, `subscribe`, `getSharedData`, `getPermissions`,
  `requestUnlock`) is a method *on this one channel*, so cross-partition reads
  added no new site-facing surface and no policy change.
- `internal:get-vault-inject-source` — PUBLIC, the document-start bootstrap, the
  same shape the ethereum provider already uses.

Owner plane (chrome renderer only, via `src/main/preload.js`, never a webview):
`datavault:usage`, `list-partitions`, `get-partition-data`, `partition-for-url`,
`delete-partition`, `clear-all`, `export`, `foreign-grants`,
`revoke-foreign-read`, `set-foreign-read-enabled`, plus the consent and
unlock-request pushes. `revoke-foreign-read` is currently reached by no UI —
the Data pane switches a grant off rather than dropping it — and is kept
because it is the owner-plane capability a maintainer would expect to exist;
say so in the PR rather than leaving a reviewer to find it.

Launcher plane: `datavault:home-status|tiles|open|unlock`. These sit at PUBLIC in
the policy file because `window.vaultHome` is exposed from the same shared
webview preload that web content loads, so the tier cannot narrow them — the
boundary is in the handler instead: all four are registered behind `homeOnly`,
which matches `event.senderFrame.url` against the internal page's own file URL,
and the manager refuses to register them at all if the host supplies no such
check. A drift test parses `webview-preload.js` so a new channel cannot appear
without a tier.

## 7. On disk

```
userData/vault-data/<sha256(namespace)>.bin   sealed document per site
userData/vault-permissions.enc                remembered grants (safeStorage)
```

The permission file is safeStorage-encrypted and deliberately **not** sealed
under the vault DEK — the browser has to read it to know what to prompt for
before anything is unlocked. It is therefore a browsing-history artefact, which
its own header says, and the engine re-clamps anything read back out of it
(a hand-edited `"/"` entry cannot widen a `/shared` grant).

Cross-partition reads added one field: `foreignReads[]` on the reader's record,
each `{namespace, origin, paths, enabled?}`. `enabled` absent means on.

## 8. The user-facing surface

**Consent sheet** (Data pane): the wallet's own Connect pane, class for class.
Two headed sections — the partition being created, shown as the exact row the
Data pane lists sites with; and, only when asked for, the other partitions this
site wants to read, each a namespace in code with one `read` checkbox. Allow /
Reject. The sheet approves **per partition, not per field**: a field path is the
site's own schema and means little to the person approving it.

A site asking to write at or below `/shared` also gets a blue note under its
row — "This site writes data marked `/shared` into its partition. Other sites
can read this data if you give them permission." It is the only place the user
is told that location is the mark, and it appears on exactly the condition the
engine's publish gate enforces, so a whole-document grant does not raise it.

**Data pane**: usage bar; "Sites with data" (each row the site's thumbnail,
origin with scheme, size and field count — the thumbnail opens the site); and
whole-vault Export and Clear, bottom-aligned.

**A partition's detail page** reads THIS PARTITION → PERMISSIONS → STORED DATA
→ delete. The partition is that same site row. Permissions is one section
holding both directions of cross-origin read, each a one-line item — the other
partition's namespace and a `read` checkbox — told apart three ways and never
by hue alone: a sub-label in words ("This site reads" / "Reads this site"), an
arrow, and a left edge that is accent going out, green coming in, and grey when
the read is switched off. Unticking either end switches the same grant off and
keeps it, so it can be switched back on; nothing on the page removes a grant,
which is deliberate.

A per-tab banner says which partition belongs to the page in front of you, in
the same shape as the wallet/Swarm/x402 banners. Any interaction with the pane
re-reads the lock state, so a vault that auto-locked behind an open pane raises
its prompt over everything on the next click.

**`freedom://dapps`**: tiles for the sites holding data, icon or monogram, opens
a site by namespace only — the page never passes a URL, so the launcher cannot be
turned into "navigate anywhere". Read-only, `connect-src 'none'`, and it shows
nothing while the vault is locked.

**Locked vault**: the Data pane shows an unlock prompt and nothing else — not
even the site count, because the set of sites you hold data for is
history-shaped. The vault has no unlock UI of its own; one unlock covers the
identity vault and this one, and every caller checks the lock state before
raising the browser's unlock screen (that screen *shows* an unlock, it does not
decide one is needed).

## 9. Tests

- **Engine (vitest, separate repo):** the grant arithmetic, pointer units, and
  50+ tests for cross-partition reads — including a no-oracle test asserting
  `toEqual` between an unapproved owner and a never-visited one, "a
  whole-document read grant confers no foreign access", gating order, caps,
  consent narrowing and clamping, and the publish gate.
- **End to end (jest, this repo):** `data-vault-crossread.test.js` stubs
  nothing below the IPC boundary — real keystore over a real mnemonic, real
  blob store over a temp directory, the real vendored engine, the real grant
  store — and drives it the way a page does, through `_onRequest` with an
  authoritative `senderFrame.url`. It exists because the feature's one
  load-bearing claim is the hardest thing to see in a unit test: that a granted
  read comes back with the owner's VALUE in it. Everything around it answers
  `null` by design, so a wiring mistake anywhere in the chain looks exactly
  like the no-oracle behaviour working. It also pins what only an end-to-end
  shows: a wholesale grant picking up what the owner publishes later, the Data
  pane's checkbox stopping and restoring a live read without re-prompting,
  owner deletion refusing the reader's session and making it ask again while
  leaving its own grant intact, and the publish gate.
- **Host (jest, this repo):** 3 more suites, the first unit tests under
  `src/main/vault/` — the namespace-aware `covers()`, `vault_getSharedData`
  routing and its refusals (wrong tab → `4900` with the engine never called),
  `params.origin` forwarded verbatim, the always-granted set excluding the
  cross-origin method, grant persistence including `foreignReads` clearing on
  re-consent, and the injected provider's surface.
- **Renderer:** 59 tests for the Data pane against a hand-rolled fake DOM (no
  `jest-environment-jsdom` in this project). The fake records `innerHTML` writes
  rather than emulating them, so the assertions are about which API the module
  reached for: a site-chosen pointer that survives as `textContent` cannot have
  been parsed. It returns NodeList-*like* objects deliberately — handing back an
  Array once let `rows.some(...)` pass 35 tests and throw in the browser.
- Whole suite: **8,257 passing**, lint clean, the colour-literal ratchet empty,
  `npm run test:coverage` green, and `licenses-audit.test.js` green *while
  enforcing this feature's own vendor directory*. Each of the five commits was
  checked out and run on its own, not just the tip.
- Note for whoever reads CI: `upstream/main` is itself red at `52cd49bc` on
  three `tabs-ui` tests (#717, "select tab by position"). Confirmed in a
  pristine worktree of upstream — not this branch.

Guards were mutation-tested as they were written: reverting the fix reddens a
named test, and that is recorded in the commit messages.

## 10. Limits

| Limit | Value | Enforced |
| --- | --- | --- |
| Per-site document | **16 MiB**, on the UTF-8 serialization | engine, inside the write lock — `QuotaExceeded` |
| Nesting depth | 32 levels, counted from the document root | same |
| Pointer length | 512 UTF-8 bytes | `parsePointer` |
| Paths per read / subscribe | 64 | per method |
| Changes per write | 128, for `set` and `patch` alike | one chokepoint |
| Cross-origin reads | 8 owners, 16 paths each | at connect |
| Icon a site may send | 16 KiB decoded, 8–512 px | host, re-encoded to a 128×128 PNG |

**There is no total-vault quota**, and that is deliberate rather than
overlooked: the vault grows with the sites the user approves, one partition per
origin, each needing a consent approval. So the ceiling is the user's own
approvals × 16 MiB, and the usage bar shows composition rather than filling
toward a number nobody set.

Two costs worth knowing before the first bug report:

- **Every write is a whole-document read-modify-write** — load, decrypt, parse,
  mutate, serialize, encrypt, save — so one small `set` costs what the partition
  holds, not what changed. The per-site cap is therefore also the worst case of
  a single call, which is why it is 16 MiB and not larger. Nothing throttles
  writes.
- **`getUsage()` is O(partitions) in `stat` calls**, and the Data pane calls it
  on every interaction (that is how it notices a vault that auto-locked behind
  an open pane). At a few hundred partitions that is a few hundred syscalls per
  click. Cheap to fix with a cache invalidated on `partition-changed`; left as a
  follow-up rather than guessed at.

## 11. Decisions, and what was rejected

| Decision | Why | Rejected |
| --- | --- | --- |
| `/shared` as a reserved subtree | location is the mark; cannot be mis-set | a per-field `shareable` flag |
| Read-only cross-partition access | a cross-origin write is a different feature with a different threat model | cross-origin `set`/`patch` |
| No cross-origin `subscribe` | a push channel across partitions is a side channel | polling, which this forces |
| Reads declared at `connect` | one sheet covers everything a site wants | a second mid-session prompt |
| Absent reads as `null`, no error code | any distinction is an existence oracle over browsing history | a `NoSuchOwner` error |
| Approve per partition | a JSON Pointer means nothing to the person approving it | per-field toggles (built first, then removed) |
| A separate `Grant.foreignReads` list and a separate checker | if one list answered both questions, an absent namespace would be a wildcard | `namespace?` on `FieldRule` |
| No new site-facing channel | `vault:provider-request` is already the one surface | `vault:get-public-data` |
| Switch a read off, keep the grant | the user's "off" should be restorable without re-approving paths | remove-only |
| One `enabled` flag, toggled from either end | it is one grant; a live colour on the owner's page for a read the reader switched off said it was on | a per-side state |
| The row names the partition, not its pointers | a JSON Pointer means nothing to the person approving it, and `/shared` on every row said nothing | listing paths on the row |

## 12. Accepted risks, stated plainly

- **Residual timing channel.** An approved-but-empty owner costs a manifest load
  and a decrypt; an unapproved owner short-circuits first. Closing it fully means
  decrypting on every rejected call, which is a free DoS.
- **Uniform-empty is undebuggable by construction.** A typo'd origin, a
  granularity mismatch, an unticked row and a never-visited site look identical
  to the developer. Mitigated only on the vault's own surfaces (a main-process
  log line, the approved pairs in the Data pane); nothing reaches the page.
- **No subscribe will produce polling.** A per-(reader, owner) read budget is
  the obvious next step, and an exhausted budget must return the same uniform
  nulls — a "rate limited" reply is itself a signal.
- **The permission file encodes cross-site edges.** B's record proves the user
  visited A.
- **The consent sheet is now the whole boundary.** It asks the user to recognise
  a second-party origin mid-flow. That is the weakest link, and it is UI work.
- **A reader can re-publish what it reads.** The grant is per pair and not
  transitive, but the data is not bound at all: revoking stops future reads, not
  past copies. The site-author guide says this in those words.

## 13. What the maintainers would own, and what they would not

Taking the PR means owning: the host glue in `src/main/vault/`, the Data pane,
the launcher, the IPC surface and the docs — ordinary Freedom code in Freedom's
style, with tests.

It does not mean owning the cryptography or the grant arithmetic: those live in
the engine repo and arrive as a generated bundle. That is the trade to be
explicit about — and the paperwork around it is done rather than promised: the
engine is MPL-2.0 like Freedom, the banner says which revision is in the tree,
the README says how to rebuild it, and `licenses-audit.test.js` fails if any of
the three licensing records falls out of step. What a maintainer still inherits
is the dependency itself: a security fix in the engine means a bundle commit
here, from a repository they do not control.

## 14. Running it

```bash
npm start                       # the branch runs as-is; the vault registers at boot
npm test                        # 7,645 tests
npm run lint
npm run styles:inventory -- --write   # colour-literal ratchet; expect an empty diff
```

A three-site mock for the cross-partition flow lives in this repo at
[`examples/shared-reads-mock/`](../examples/shared-reads-mock/) (`pnpm
serve:shared-reads`): two owners and a reader, one port, distinct hosts. Its
README gives the order to drive it in, which matters — a reader that asks
before the owner publishes reads `null`, and so does a broken wiring. The host matters — `*.localhost` namespaces are keyed by host *and*
port, so `owner.localhost:8799` and `owner2.localhost:8799` are two partitions
— and the second owner exists so a reader can ask for one owner, have it
remembered, and then ask for two.
