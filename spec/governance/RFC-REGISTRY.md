# RFC-REGISTRY — ACP RFC Registry

| Field | Value |
|---|---|
| **Status** | Normative |
| **Version** | 1.0 |
| **Type** | Registry |
| **Maintained by** | ACP Editor |
| **Date** | 2026-03-10 |

---

## Description

Official registry of all RFCs submitted to the ACP process. Includes accepted, rejected, and withdrawn RFCs. No RFC may advance to `Implemented` status without being registered here.

See full process in [`RFC-PROCESS.md`](./RFC-PROCESS.md).

---

## Registry

| rfc_id | title | type | author | date_opened | date_closed | status | breaking | version_impact | link |
|--------|-------|------|--------|-------------|-------------|--------|----------|----------------|------|
| — | — | — | — | — | — | — | — | — | — |

*No RFCs registered as of this date.*

---

## Notes

- `rfc_id`: Unique identifier assigned by the Editor (format: `RFC-YYYY-NNN`)
- `type`: `Informational` / `Protocol` / `Extension`
- `status`: `Draft` / `Open` / `Accepted` / `Rejected` / `Withdrawn` / `Implemented`
- `breaking`: `Yes` / `No`
- `version_impact`: List of affected documents and versions (e.g. `ACP-LEDGER-1.2, ACP-CONF-1.1`)
- `link`: Relative path to the RFC document (e.g. `./rfcs/RFC-2026-001.md`)
