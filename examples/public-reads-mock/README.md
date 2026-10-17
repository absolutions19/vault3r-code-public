# Cross-partition `/public` reads — a three-site mock

Three sites on one port, routed by `Host`, for exercising the whole
publish-and-read flow by hand in Freedom:

| Origin | Role |
| --- | --- |
| `http://owner.localhost:8799` | publishes under `/public` |
| `http://owner2.localhost:8799` | a second, independent owner |
| `http://reader.localhost:8799` | asks to read one or both owners' `/public` |

No dependencies, no build:

```bash
pnpm serve:public-reads          # or: node examples/public-reads-mock/server.mjs
```

The **host matters**. Namespaces are derived from the origin including scheme,
and `*.localhost` names are keyed by port as well, so these are three separate
partitions — `web:owner.localhost:8799`, `web:owner2.localhost:8799`,
`web:reader.localhost:8799`. Chromium resolves any `*.localhost` name to
loopback, so nothing needs a hosts-file entry.

## The order that matters

A reader that asks before an owner has published reads `null`, and `null` is
also what an unapproved owner, a never-visited owner and an out-of-`/public`
path return — by design, so the page cannot probe the user's history. So do the
owner first, or the reader looks broken when it is working:

1. **Owner** → **Connect** (the consent sheet should carry the blue `/public`
   note, because the site asks to write there) → **Publish**.
2. **Reader** → **Connect — one named pointer** (the sheet lists the owner's
   partition with a `read` checkbox) → **Read /public/displayName** → the
   owner's value comes back.
3. **Reader** → **Try reading the owner's /private/notes** → `null`, with no
   error.
4. **Reader** → **Compare an unapproved owner with a nonexistent one** → the two
   answers are identical.
5. Wallet sidebar → **Data** → the reader's partition → **Permissions**: untick
   `read`, then read again → `null`. Tick it back on → the value returns.
6. **Owner** → **3 · The publish gate** → a whole-document grant is refused a
   write under `/public`, and still writes everywhere else.

**Connect — naming BOTH owners** exists for one case worth seeing: switch a
granted read off, then connect asking for a second owner. The sheet re-prompts
with both owners ticked, so approving the new one turns the old one back on.
