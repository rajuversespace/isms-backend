# ISMS Compliance Platform — Rust Backend

## Project Overview

This is the backend for an **Information Security Management System (ISMS)** compliance platform — a Vanta competitor. The Rust backend replaces the legacy TypeScript/Fastify backend that lived in `../` (the parent `isms-backend/` directory).

The platform manages compliance frameworks (ISO 27001, SOC 2, etc.), controls, policies, audits, findings, assets, risks, personnel, trust centers, and integrates with Vanta to import real compliance data.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust (stable) |
| Web Framework | Actix-web 4 |
| Database | MongoDB 7 (`mongodb` crate, async driver) |
| Auth | JWT (HS256) via `jsonwebtoken` crate |
| Serialization | `serde` + `serde_json` + `bson` |
| Password Hashing | `bcrypt` crate (12 rounds) |
| HTTP Client | `reqwest` (for Vanta API sync) |
| Config | `dotenv` + environment variables |
| Error Handling | `thiserror` + custom `AppError` enum |
| Logging | `tracing` + `tracing-subscriber` |
| Testing | `actix-web::test` + `tokio::test` |

## Architecture

```
rust-api/
├── CLAUDE.md           # This file — project memory
├── AGENT.md            # Agent behavior guidelines
├── NOPE.md             # Forbidden actions
├── .claude/            # Claude Code rules and skills
├── Cargo.toml
├── .env.example        # Template (NEVER commit .env)
└── src/
    ├── main.rs         # Entry point, server startup
    ├── config/
    │   └── mod.rs      # Env var loading, AppConfig struct
    ├── db/
    │   └── mod.rs      # MongoDB connection, database handle
    ├── errors/
    │   └── mod.rs      # AppError enum, ResponseError impl
    ├── middleware/
    │   ├── auth.rs     # JWT extraction + validation
    │   └── rbac.rs     # Role-based access control guard
    ├── models/         # Shared types (pagination, responses)
    │   └── mod.rs
    └── modules/
        ├── auth/       # Login, register, token refresh
        ├── users/      # User CRUD, role management
        ├── setup/      # System initialization (first-run)
        ├── frameworks/ # Compliance frameworks
        ├── controls/   # Security controls
        ├── policies/   # Policy documents
        ├── audits/     # Audit management
        ├── findings/   # Audit findings
        ├── assets/     # IT asset inventory
        ├── risks/      # Risk register
        ├── evidence/   # Evidence/document management
        ├── tests/      # Compliance tests
        ├── trust/      # Trust center (public)
        ├── settings/   # Organization settings
        ├── integrations/ # Third-party integrations
        └── vanta/      # Vanta API sync service
```

Each module follows the pattern:
```
modules/{name}/
├── mod.rs       # Module exports
├── routes.rs    # Route registration (web::scope + web::resource)
├── handlers.rs  # Request handlers (thin — delegate to services)
├── models.rs    # Request/response DTOs, MongoDB document structs
└── services.rs  # Business logic, database queries
```

## Database — MongoDB

- **Connection**: `mongodb://localhost:27017/isms`
- **Docker**: `docker run -d --name isms-mongo -p 27017:27017 mongo:7`
- **Collections**: lowercase plural (`users`, `frameworks`, `controls`, `policies`, etc.)
- **ObjectId**: Use `bson::oid::ObjectId`, serialize with `#[serde(rename = "_id")]`
- **Timestamps**: `created_at` / `updated_at` as `bson::DateTime`
- **References**: Store as `ObjectId`, NOT embedded documents (for 1:many relationships)

## Auth & RBAC

### JWT
- Algorithm: HS256
- Secret: `JWT_SECRET` env var
- TTL: Configurable via `JWT_EXPIRES_IN` (default: "24h")
- Payload: `{ sub: user_id, email, role, org_id, exp, iat }`
- Header: `Authorization: Bearer <token>`

### Roles (highest to lowest)
1. `SUPER_ADMIN` — Full system access
2. `ADMIN` — Organization admin
3. `COMPLIANCE_MANAGER` — Manage compliance items
4. `AUDITOR` — View + audit access
5. `EDITOR` — Edit access to assigned items
6. `VIEWER` — Read-only access

### Permissions (23 total)
See `src/middleware/rbac.rs` for the full permission matrix. Key pattern:
- `{entity}:read`, `{entity}:write`, `{entity}:delete`
- Entities: users, assets, risks, controls, evidence, audits, policies, settings, integrations, reports, findings, trust

## API Design

- **Base**: `http://localhost:8080/api/v1`
- **Format**: JSON request/response
- **Response envelope**:
  ```json
  {
    "data": { ... },
    "error": null,
    "meta": { "page": 1, "per_page": 20, "total": 100 }
  }
  ```
- **Error response**:
  ```json
  {
    "data": null,
    "error": { "code": "UNAUTHORIZED", "message": "Invalid token" }
  }
  ```
- **Pagination**: `?page=1&per_page=20` query params
- **CORS**: Allow `http://localhost:5173` (frontend dev server)

## Vanta Integration

- **Base URL**: `https://api.vanta.com`
- **Auth**: OAuth2 client_credentials -> `POST /oauth/token`
- **Scopes**: `vanta-api.all:read vanta-api.all:write`
- **Token TTL**: 1 hour, single active token per app
- **Rate Limits**: 50 req/min (management), 5 req/min (auth)
- **Pagination**: Cursor-based (`pageSize` + `pageCursor`)
- **Key endpoints**: `/v1/frameworks`, `/v1/controls`, `/v1/tests`, `/v1/documents`, `/v1/people`, `/v1/policies`
- **Credentials**: Loaded from env vars `VANTA_CLIENT_ID` and `VANTA_CLIENT_SECRET` — NEVER hardcoded

## Frontend

- **Location**: `../../Manzen/` (sibling to `isms-backend/`)
- **Stack**: React 18 + Vite + TailwindCSS 4 + Radix/shadcn + TanStack Query
- **API services**: `Manzen/src/services/api/` — 21 service files
- **API client**: `Manzen/src/services/api/client.ts` — base URL from `VITE_API_URL`
- **Auth**: JWT stored in localStorage as `isms_token`
- **Dev server**: `http://localhost:5173`

## GitHub

- **Repo**: `rajuversespace/isms-backend` (fork of `vinmnit159/isms-backend`)
- **Issues**: 21 issues across 7 phases — see GitHub Issues tab
- **Branch strategy**: Feature branches per issue -> PR to main
- **CLI**: Authenticated as `rajuversespace`

## Key Commands

```bash
# Build
cargo build

# Run (dev)
cargo run

# Run with auto-reload
cargo watch -x run

# Tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# MongoDB (Docker)
docker run -d --name isms-mongo -p 27017:27017 mongo:7

# Check MongoDB
docker exec -it isms-mongo mongosh --eval "db.adminCommand('ping')"
```

## Environment Variables

```bash
# Server
HOST=127.0.0.1
PORT=8080
RUST_LOG=info

# Database
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=isms

# JWT
JWT_SECRET=<random-secret>
JWT_EXPIRES_IN=24h

# CORS
CORS_ORIGIN=http://localhost:5173

# Vanta (for sync service)
VANTA_CLIENT_ID=<from-vanta-dashboard>
VANTA_CLIENT_SECRET=<from-vanta-dashboard>

# Bcrypt
BCRYPT_COST=12
```

## Reference: Legacy TypeScript Backend

The original TypeScript backend is in the parent directory (`isms-backend/`). Key reference files:
- `../prisma/schema.prisma` — 30+ data models (source of truth for MongoDB schema design)
- `../src/lib/rbac.ts` — Role/permission definitions
- `../src/lib/seed.ts` — ISO 27001 controls (93) + default policies (26)
- `../src/modules/` — 18 modules with full route/handler/service implementations
