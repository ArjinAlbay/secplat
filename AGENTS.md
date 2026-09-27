# AGENTS.md

SecPlat: orchestration platform for ProjectDiscovery security tools (v1: nuclei only).
Monorepo: `backend/` (Python 3.13, FastAPI + Celery + SQLAlchemy 2, managed by `uv`),
`frontend/` (Next.js 16 + React 19, npm), root `docker-compose.yml` (postgres 18.6, redis, api, worker, beat, frontend).
Not a git repo yet — no commit/branch conventions apply.

## Commands

Backend (run in `backend/`):

```
uv sync                                  # creates .venv AND uv.lock — must run before docker build
uv run ruff check src tests              # lint (line 100; E/F/I/UP/B; --fix for autofix)
uv run lint-imports                      # layer contracts — MUST pass, not optional
uv run pytest                            # 20 tests; needs no services (sqlite + FakeTaskQueue + stub nuclei script)
uv run alembic upgrade head              # migrations; DB URL comes from SECPLAT_DATABASE_URL
```

Frontend (run in `frontend/`): `npm install` (generates package-lock.json, required by the Dockerfile's `npm ci`) then `npm run build`. There is intentionally **no lint script** — `next lint` was removed in Next 16.

Full stack: `make up` (build + start), `make down`, `make migrate`, `make templates`, `make test`, `make lint`, `make api/worker/beat` (local dev servers). `make help` lists all.

Verification order after backend changes: `ruff check` → `lint-imports` → `pytest`. All three via `uv run`, from `backend/`.

## Architecture (enforced, not just convention)

- DDD layers `presentation > infrastructure > application > domain` enforced by import-linter in `backend/pyproject.toml`. The domain layer (`src/secplat/domain/`) is pure Python — importing sqlalchemy/celery/pydantic/fastapi there breaks a contract and `lint-imports`.
- Tools are infrastructure adapters behind the `ToolAdapter` protocol (`domain/scanning/ports.py`). Adding a new tool = new `infrastructure/tools/<tool>/adapter.py` + register in `infrastructure/tools/__init__.py:get_adapter` + extend `ToolName` enum + config DTO. Domain/application layers stay untouched.
- nuclei flag policy lives in the adapter: forced args (`-jsonl -silent -nc -duc`), allowed config keys only, everything else → `ConfigNotAllowed` (also blocked at the API by pydantic `extra="forbid"`). Never add a flag without classifying it.
- Outbox pattern in `StartScan`: save(pending) → mark_queued(preassigned task_id) → save → enqueue with that task_id; publish failure fails the scan. QUEUED is always committed before the message exists, so a fast worker can never observe PENDING. Same order in the watchdog requeue path. `ExecuteScan` only runs from status QUEUED (idempotent against requeue); results stream in batches (BATCH_LINES=50 / BATCH_SECONDS=2.0).
- Watchdog (`reconcile_stale_scans`, beat, 60s): RUNNING + updated_at stale > scan_timeout+300s → fail; PENDING > 5 min without task_id → requeue.
- Scan status machine: `pending→queued→running→completed|failed|cancelled`. Domain errors map to HTTP: NotFound* → 404, InvalidTransition → 409, other DomainError → 400 (handler in `presentation/main.py`).

## Env & config

- Settings: pydantic-settings with `SECPLAT_` prefix (`infrastructure/config.py`, `get_settings()` is lru_cached — tests override env before first import or it won't take).
- `docker-compose.yml` requires `.env` at repo root (copy from `.env.example`). Container URLs use service names (`postgres`, `redis`); host-side URLs need `localhost:5434` — **host port is 5434, not 5432** (host PG owns 5432, another project's container owns 5433).
- Host-side migration: `SECPLAT_DATABASE_URL=postgresql+psycopg://secplat:devpass@localhost:5434/secplat uv run alembic upgrade head`.

## Docker / ops gotchas (all hit in practice)

- `backend/Dockerfile` uses `uv sync --frozen --no-dev --no-editable` → **uv.lock must exist and be fresh** (run `uv sync` first). `COPY src` happens before `uv sync` on purpose.
- PG 18 requires the volume mounted at `/var/lib/postgresql` (NOT `/var/lib/postgresql/data` — container exits with a misleading "existing data" error).
- Celery beat must run with `--schedule /tmp/celerybeat-schedule` (compose already does); default cwd `/app` is not writable by the `scanner` user and beat crash-loops otherwise.
- The image runs as `scanner` (uid 10001) created with `useradd -r -m` — the home dir is required (nuclei writes `~/.config/nuclei`).
- nuclei binary: pinned v3.11.1, checksum-verified. `sha256sum -c` needs the original filename — download with `curl -O`, not `-o nuclei.zip`. The release zip contains README/LICENSE files; extract only the `nuclei` member.
- **nuclei template downloads from the vendor CDN time out on this network.** `make templates` / `-ut` may fail. Working workaround: download the GitHub release archive of `nuclei-templates` (tag matching installed version), unzip, `docker cp` into `secplat-worker-1:/opt/nuclei-templates/` (named volume, persists across rebuilds).

## Data / behavior quirks

- nuclei emits **duplicate JSONL lines** (same template-id + matched-at, e.g. TLS findings per protocol version). Dedup is by fingerprint `sha256(template_id|matched_at or host)`: an in-scan `seen` set in `ExecuteScan` + unique constraint `uq_findings_scan_fingerprint`. There is a regression test for this — don't remove the seen-set.
- Repository writes go through `_commit()` (`persistence/repositories.py`) which rolls back on failure — this is what lets `scan.fail()` be persisted after a mid-scan DB error (otherwise the session is stuck in PendingRollback and the scan hangs in RUNNING).
- A scan that finishes `completed` with **0 findings AND 0 raw results usually means the target was unreachable from the worker** (e.g. target firewall drops the scanner IP) — nuclei exits 0. Don't read it as "clean site". Check `GET /scans/{id}/results` count.
- SQLAlchemy enums store `.value` (lowercase) via `values_callable`; use `StrEnum`, not `str, Enum` (ruff UP042).

## Testing quirks

- Tests use sqlite via `tmp_path` + `Base.metadata.create_all` (no alembic); ORM types use `.with_variant()` for sqlite/pg compat — keep that when adding columns.
- Integration tests drive the FastAPI app via `TestClient` with `app.dependency_overrides` on `get_db` and `get_task_queue` (`tests/conftest.py`); the worker side (`ExecuteScan`) is invoked manually with a stub nuclei script (python file printing JSONL).
- `tests/` has `__init__.py` files — required for `from tests.conftest import ...` to resolve. Keep them.
- The duplicate-finding scenario in `test_scan_flow.py` stub is load-bearing (see dedup quirk above).

## Frontend notes

- Next 16: page `params` is a Promise — pages use the `useParams()` hook instead of destructuring props. Scan detail page polls every 2s until terminal; sidebar polls every 5s.
- API client is a single file: `frontend/src/lib/api.ts` (`NEXT_PUBLIC_API_URL`, default `http://localhost:8000`). Update types there when backend DTOs change.
- Build output is `standalone` (Dockerfile runs `node server.js`).

## Style (repo-specific)

- No comments in code, no README — both deliberate; don't add them.
- `from __future__ import annotations` at the top of every Python module; type hints everywhere.
- API JSON is snake_case; response DTOs have `from_domain`/`from_view` constructors — routes never return domain objects directly.
