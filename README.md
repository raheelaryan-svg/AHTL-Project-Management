# AHTL Project Management Portal — cloud starter (based on v95)

## What is included
- Existing v95 portal UI modified to load/save one PostgreSQL-backed shared JSON state over an authenticated API.
- FastAPI backend, PostgreSQL database, Docker Compose, basic role-based login, revision-conflict detection, server audit entries.
- Separate authenticated attachment upload/download endpoints (not yet wired to the legacy UI).
- `.gitignore` prevents secrets and live database files from entering GitHub.

## Deployment
1. Create a **private** GitHub repository and upload these source files (never `.env` or actual data).
2. Deploy to a Docker-capable cloud VM with persistent storage; install Docker and Docker Compose.
3. Copy `.env.example` to `.env` and replace **all** placeholders with long unique secrets.
4. Run `docker compose up -d --build` from the repository root.
5. Configure a reverse proxy with a domain and HTTPS to `127.0.0.1:8000`. Do not expose port 8000 directly to the internet.
6. Open the HTTPS site and sign in using the configured server password: `ADMIN_PASSWORD` for EP/Approver, `ROLE_PASSWORD` for other roles.
7. Export a JSON backup from the old v95 browser and import it into the server portal using Audit & Data after login. **Back up your server before importing.**

## Important limitations — not production-ready without additional work
- This is an **integration starter**, not a finished enterprise deployment. The frontend's role-based controls are inherited from v95; server authorization is only coarse. Do not expose confidential projects until per-user accounts, record-level access checks, secure account administration, and a security review are implemented.
- All portal data is saved as one JSON document in PostgreSQL. Optimistic revision checks prevent silent overwrites, but simultaneous edits may require reloading and re-entering changes. A normalized database with per-record updates is recommended for true concurrent editing.
- The existing v95 UI still embeds attachment content in JSON. Dedicated server attachment endpoints exist but **are not connected to the UI**. Large attachments may fail at the 15 MB state limit. Migrate attachments before production.
- Login uses shared passwords per role from server environment, not personal accounts. Role Settings in the legacy UI does not change server login passwords.
- The portal's legacy email, password-verification prompts and audit entries are not authoritative server-side enforcement. Manager approvals and deletions need server-side policy enforcement before live use.
- Changes are visible to other users on next page reload/login; there is no real-time push.
- `workflow` starts empty on a new server; use your v95 JSON backup to preserve workflow and projects. New-project creation should be tested after import.
- Back up PostgreSQL volumes and attachment storage regularly, and test restoration. Use private repository and HTTPS.

## Quick verification
`docker compose config` then `docker compose up -d --build`; visit `/api/health`.
