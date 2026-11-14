# MCP

Rozhanitsy runs an [MCP](https://modelcontextprotocol.io) server so AI agents can query the vulnerability data directly.
It answers the same questions as the API (the check goes through the same `App\Services\ComponentChecker`), plus remediation, recent changes and data freshness.

The server lives at `POST /mcp` (streamable HTTP), is public (no auth) and is throttled to 60 requests per minute per IP (the `mcp` rate limiter in `AppServiceProvider`).
Every tool is read-only.

## Connecting

Claude Code:

```bash
claude mcp add --transport http rozhanitsy https://rozhanitsy.example.com/mcp
```

Any other client that speaks streamable HTTP:

```json
{
    "mcpServers": {
        "rozhanitsy": {
            "type": "http",
            "url": "https://rozhanitsy.example.com/mcp"
        }
    }
}
```

To poke at it by hand, `php artisan mcp:inspector mcp` opens the MCP Inspector against the local server.

## Tools

| Tool                                      | What it does                                                          |
| ----------------------------------------- | --------------------------------------------------------------------- |
| [`check-component`](#check-component)     | is a product version vulnerable, and which version fixes it           |
| [`get-vulnerability`](#get-vulnerability) | everything known about a CVE / GHSA / OSV id                          |
| [`get-remediation`](#get-remediation)     | the fixed version per affected package, plus patch and advisory links |
| [`recent-changes`](#recent-changes)       | vulnerabilities published or modified lately                          |
| [`source-status`](#source-status)         | how fresh the data is, per source                                     |

Results come back as structured content (and the same JSON as text for clients without structured output support).
Invalid arguments and unknown ids come back as tool errors, e.g. `No vulnerability found for [CVE-2099-0001].`

### check-component

Same as `GET /api/v1/check`, see the [API](API) page for the full rules: what gets searched, confidence, ambiguity and version comparison.

| Argument                 | Required | Notes                                                                                               |
| ------------------------ | -------- | --------------------------------------------------------------------------------------------------- |
| `product`                | yes      | CPE product (NVD) or package name (OSV)                                                             |
| `version`                | yes      | version to check                                                                                    |
| `vendor`                 | no       | NVD vendor, narrows the search and finds CNA-only records                                           |
| `ecosystem`              | no       | OSV ecosystem, e.g. `npm`, `PyPI`, `Debian:12`. Distro ecosystems are only searched when named here |
| `severity`               | no       | `LOW`, `MODERATE`, `MEDIUM`, `HIGH` or `CRITICAL`                                                   |
| `min_score`              | no       | `0` to `10`                                                                                         |
| `include_low_confidence` | no       | boolean, default `false`                                                                            |

Returns the same object as the API's `data`. When it comes back `ambiguous: true`, call it again with one of the `candidates`.

### get-vulnerability

| Argument | Required | Notes                                          |
| -------- | -------- | ---------------------------------------------- |
| `id`     | yes      | e.g. `CVE-2021-44228` or `GHSA-jfh8-c2jp-5v3q` |

Same lookup and record shape as `GET /api/v1/vulnerabilities/{id}`: one record per source, including records filed under one of its aliases. Withdrawn / rejected records are included, check `status`.

```json
{
    "id": "CVE-2021-44228",
    "records": [{ "...": "same shape as the API vulnerability details" }]
}
```

### get-remediation

| Argument                         | Required | Notes                                           |
| -------------------------------- | -------- | ----------------------------------------------- |
| `id`                             | yes      | e.g. `CVE-2021-44228`                           |
| `vendor`, `product`, `ecosystem` | no       | only fixes for ranges matching all given values |

Looks the id up like `get-vulnerability`, skips withdrawn / rejected records and lists one fix per affected range (`version_scope` `range` or `any`).

```json
{
    "id": "CVE-2021-44228",
    "fixes": [
        {
            "source": "osv",
            "record_id": "GHSA-jfh8-c2jp-5v3q",
            "fixed_in": "2.15.0",
            "confidence": "high",
            "affected_range": { "...": "same shape as affected_range in check" }
        }
    ],
    "references": [
        {
            "url": "https://logging.apache.org/log4j/2.x/security.html",
            "tags": ["Vendor Advisory"]
        }
    ]
}
```

- `fixed_in` is `null` when no fix is known
- `confidence` is `low` for a range with `version_scope: any` or `confidence: low`, same as in check
- `references` are only the ones tagged `Patch`, `Mitigation`, `Vendor Advisory`, `Release Notes` (NVD) or `FIX`, `ADVISORY` (OSV), deduplicated by URL

### recent-changes

| Argument                         | Required | Notes                                                         |
| -------------------------------- | -------- | ------------------------------------------------------------- |
| `since`                          | no       | date or datetime, default 7 days ago                          |
| `vendor`, `product`, `ecosystem` | no       | only records with an affected range matching all given values |
| `severity`                       | no       | `LOW`, `MODERATE`, `MEDIUM`, `HIGH` or `CRITICAL`             |
| `known_exploited`                | no       | boolean (CISA KEV)                                            |
| `limit`                          | no       | 1-100, default 25                                             |

Lists records whose `last_modified_at` is on or after `since`, most recently modified first. Withdrawn / rejected records are left out.

```json
{
    "since": "2026-10-27T00:00:00+00:00",
    "has_more": false,
    "vulnerabilities": [
        {
            "id": "CVE-2026-2000",
            "source": "nvd",
            "aliases": [],
            "change": "published",
            "description": "Remote code execution.",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "known_exploited": false,
            "published_at": "2026-10-30T00:00:00+00:00",
            "last_modified_at": "2026-10-31T00:00:00+00:00"
        }
    ]
}
```

- `change` is `published` when `published_at` is on or after `since`, else `modified`
- `has_more` is `true` when `limit` cut the list short, ask again with a later `since` or narrower filters

### source-status

No arguments. One entry per source, use it to tell whether a recent vulnerability can be in the data yet.

```json
{
    "sources": [
        {
            "slug": "nvd",
            "name": "NVD",
            "url": "https://nvd.nist.gov/",
            "last_synced_at": "2026-11-03T06:00:00+00:00",
            "latest_record_modified_at": "2026-11-03T05:42:11+00:00",
            "parsed_records": 312000,
            "unresolved_records": 0,
            "pending_records": 0,
            "failed_records": 3
        }
    ]
}
```

| Field                       | Meaning                                                            |
| --------------------------- | ------------------------------------------------------------------ |
| `last_synced_at`            | last successful ingest, `null` before the first one                |
| `latest_record_modified_at` | newest `last_modified_at` among the parsed records                 |
| `parsed_records`            | records that went through `parse:l1`                               |
| `unresolved_records`        | parsed records `parse:l2` hasn't resolved into version ranges yet  |
| `pending_records`           | ingested records waiting for `parse:l1`                            |
| `failed_records`            | ingested records `parse:l1` failed on, retry with `--retry-failed` |
