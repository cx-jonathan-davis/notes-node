# notes-node

A small Express + SQLite "Notes" app. It exists to be a **clean baseline** for Checkmarx
scanning: intentionally vulnerable PRs get opened against it later, and every finding they
produce should be attributable to the PR rather than to this starting point.

Sibling repos `notes-python` and `notes-java` implement the same routes, so a vulnerability
introduced here has a direct counterpart in the other two.

## Running it

```bash
npm install
npm start          # http://127.0.0.1:3000
```

The SQLite database is created and seeded on first start. Demo account: `demo` / `demo-password`.

## Routes

| Route | Purpose |
|---|---|
| `GET /` | List all notes, plus the "add note" form |
| `GET /notes/:id` | View a single note |
| `POST /notes` | Create a note (`title`, `body`) |
| `GET /search?q=` | Search titles and bodies |
| `GET /login`, `POST /login` | Session login |
| `POST /logout` | Destroy the session |
| `GET /attachments/*` | Serve a file from `uploads/` |
| `GET /health` | Liveness probe |

## Seams for vulnerability injection

Each route below is written securely *now*. The right-hand column is where a later PR would
introduce the corresponding flaw — listed so the three language repos stay in sync.

| Seam | File / function | Currently | Flaw a PR would introduce |
|---|---|---|---|
| SQL | `src/db.js:searchNotes()` | Prepared statement, wildcards in the bound value | SQL injection via template-literal concatenation |
| SQL | `src/db.js:getNote()` | Prepared statement | SQL injection on the id |
| HTML | `views/index.ejs`, `note.ejs` | `<%= %>` (escaping) | Stored XSS by switching to `<%- %>` |
| Filesystem | `src/routes/attachments.js` | Resolves, then checks the path stays under root | Path traversal by dropping the `rel` check |
| Secrets | `src/server.js` session `secret` | From `NOTES_SECRET_KEY`, random fallback | Hardcoded session secret |
| Crypto | `src/db.js:verifyPassword()` | scrypt + `timingSafeEqual` | Plaintext or MD5 comparison |
| Cookies | `src/server.js` `cookie` options | `httpOnly`, `sameSite`, `secure` in prod | Dropping `httpOnly` / `secure` |

## Why it is written this way

- **Prepared statements everywhere.** No SQL string is ever built by concatenation.
- **`<%= %>` throughout.** EJS's escaping form; no `<%- %>` is used on user data — only on
  the `include()` calls for layout partials, which take no user input.
- **Path containment before read.** `attachments.js` resolves the path and confirms it stays
  under `uploads/` *before* opening it, so `../` and absolute paths both fail closed.
- **No committed secrets.** The session secret comes from the environment.
- **Pinned dependencies**, and `npm audit` reports zero vulnerabilities as committed.
  `package-lock.json` is committed so Checkmarx SCA has a lockfile to read.
