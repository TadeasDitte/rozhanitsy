# API

All endpoints live under `/api/v1`, are public (no auth) and throttled to 60 requests per minute.
Everything returns JSON wrapped in `data`. Validation errors come back as `422` with an `errors` object.

## Check a version

`GET /api/v1/check?product=wordpress&version=6.9.2&vendor=wordpress`

| Param | Required | Notes |
|---|---|---|
| `product` | yes | CPE product (NVD) or package name (OSV) |
| `version` | yes | version to check |
| `vendor` | no | CPE vendor / purl namespace, OSV mostly has none so leave it out for packages |
| `ecosystem` | no | OSV ecosystem, e.g. `npm`, `PyPI`, `Packagist` |
| `include_low_confidence` | no | `1` / `0`, default `0`. Also return matches from ranges where the source named the product but gave no versions (see [confidence](#confidence)) |

Names are matched exactly, use [products](#search-products) to find the right spelling.

```json
{
  "data": {
    "vendor": "wordpress",
    "product": "wordpress",
    "ecosystem": null,
    "version": "6.9.2",
    "vulnerable": true,
    "vulnerability_count": 1,
    "recommended_version": "6.9.5",
    "vulnerabilities": [
      {
        "id": "CVE-2026-1000",
        "source": "nvd",
        "aliases": ["GHSA-aaaa-bbbb-cccc"],
        "description": "...",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "known_exploited": true,
        "confidence": "high",
        "fixed_in": "6.9.5",
        "affected_range": {
          "type": "a",
          "ecosystem": null,
          "package_manager": null,
          "vendor": "wordpress",
          "product": "wordpress",
          "version_incl_start": "6.9",
          "version_excl_start": null,
          "version_incl_end": null,
          "version_excl_end": "6.9.5",
          "version_scope": "range",
          "plugs_into": null
        }
      }
    ]
  }
}
```

- `fixed_in` is the exclusive end of the matched range, `null` when no fix is known (e.g. OSV `last_affected` only)
- `recommended_version` is the lowest version that fixes every high confidence match, `null` when there is none or any of them has no fix
- a record with several matching ranges is listed once
- withdrawn (OSV) and rejected (NVD) records are ignored
- the same issue from NVD and OSV shows up twice, link them through `aliases`

### Confidence

Every range has a `version_scope`:

| `version_scope` | Meaning | In `check` |
|---|---|---|
| `range` | bounds come from the source; all bounds null means every version (e.g. OSV `introduced: 0` with no fix) | always |
| `any` | NVD CPE version `*` with no bounds, NVD named the product but not which versions (mostly old, never re-analyzed CVEs) | only with `include_low_confidence=1`, `confidence: "low"` |
| `na` | NVD CPE version `-` (not applicable) with no bounds | never |

When a record has both a `range` and an `any` range matching, the `range` one wins.

NVD configurations with a top-level `AND` ("vulnerable X running on / with Y") don't produce ranges for the platform node. The platform goes into `plugs_into` instead. A platform node is one with no vulnerable matches, or, in older NVD data that marks both sides vulnerable, one with no version info while another node has some.

### Batch

`POST /api/v1/check/batch` checks up to 100 packages at once, handy for feeding it a lockfile / SBOM.

```json
{
  "packages": [
    { "product": "lodash", "version": "4.17.20", "ecosystem": "npm" },
    { "vendor": "openssl", "product": "openssl", "version": "3.0.7" }
  ]
}
```

`include_low_confidence` goes next to `packages` and applies to the whole batch. Returns `data` as a list of check results in the same order.

## Vulnerability details

`GET /api/v1/vulnerabilities/{id}`

`id` is any CVE / GHSA / OSV id. Returns every record for it from all sources, plus records that list it as an alias and records aliased by those.
So `CVE-X` also returns the GHSA advisory that aliases it and vice versa. Withdrawn / rejected records are included here, check `status`.
`404` when nothing is found.

```json
{
  "data": [
    {
      "id": "CVE-2026-2000",
      "source": "nvd",
      "aliases": [],
      "description": "Remote code execution.",
      "cvss": { "score": 7.5, "severity": "HIGH", "vector": "CVSS:3.1/...", "version": "3.1" },
      "weaknesses": ["CWE-94"],
      "references": [],
      "status": "Analyzed",
      "known_exploited": false,
      "published_at": "2026-01-01T00:00:00+00:00",
      "last_modified_at": "2026-01-02T00:00:00+00:00",
      "affected": [ { "...": "same shape as affected_range above" } ]
    }
  ]
}
```

## List vulnerabilities

`GET /api/v1/vulnerabilities?product=nginx&severity=HIGH`

Paginated, newest `published_at` first, same record shape as details. Withdrawn / rejected records are left out.

| Param | Notes |
|---|---|
| `vendor`, `product`, `ecosystem` | only records with an affected range matching all given values |
| `severity` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `known_exploited` | `1` / `0` (CISA KEV) |
| `published_since` | date, e.g. `2026-01-01` |
| `per_page` | 1-100, default 25 |
| `page` | page number |

Pagination info is in `links` and `meta` (standard Laravel paginator).

## Search products

`GET /api/v1/products?q=opens&ecosystem=npm`

Case-insensitive prefix search on product name (`q` at least 2 characters, `ecosystem` optional). Returns up to 25 vendor / product / ecosystem combos, most vulnerabilities first.

```json
{
  "data": [
    { "vendor": "openssl", "product": "openssl", "ecosystem": null, "vulnerability_count": 312 }
  ]
}
```

## Version comparison

Versions are compared by `App\Services\VersionComparator`, one ruleset for all ecosystems:

- epoch first (`1:2.0` > `9.9`)
- numeric release segment, zero padded (`1.0` == `1.0.0`, `1.9` < `1.10`)
- pre-releases before the release: `dev` < `alpha`/`a` < `beta`/`b` < `pre`/`preview`/`m` < unknown words < `rc`/`c`
- after the release: numbers (`2.30-1`) and `post`/`patch`/`p`/`sp`/`r`
- a lone trailing letter is a post-release (`1.1.1a` > `1.1.1`, openssl style)
- leading `v`, case and `+build` metadata are ignored

Ecosystem specific rules (debian `~`, rpm, maven qualifiers) aren't implemented yet.
