# API

All endpoints live under `/api/v1`, are public (no auth) and throttled to 60 requests per minute.
Everything returns JSON wrapped in `data`. Validation errors come back as `422` with an `errors` object.

## Check a version

`GET /api/v1/check?product=wordpress&version=6.9.2&vendor=wordpress`

| Param | Required | Notes |
|---|---|---|
| `product` | yes | CPE product (NVD) or package name (OSV) |
| `version` | yes | version to check |
| `vendor` | no | CPE vendor / purl namespace, OSV mostly has none so leave it out for packages. Vendors listed as aliases match each other (see [what a check searches](#what-a-check-searches)) |
| `ecosystem` | no | OSV ecosystem, e.g. `npm`, `PyPI`, `Ubuntu:24.04:LTS`, see [what a check searches](#what-a-check-searches) |
| `include_low_confidence` | no | `1` / `0`, default `0`. Also return matches that may be false alarms (see [confidence](#confidence)) |

Names are matched exactly, use [products](#search-products) to find the right spelling.

```json
{
  "data": {
    "vendor": "wordpress",
    "product": "wordpress",
    "ecosystem": null,
    "version": "6.9.2",
    "ambiguous": false,
    "candidates": [],
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
          "confidence": "high",
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

Every range also has a `confidence`. A false alarm costs more than a missed issue, so ranges a source may have wrong are stored as `low`:

| Low `confidence` range | Why |
|---|---|
| a CNA range with no lower bound, for a CVE NVD has not analyzed yet, of a product that backports fixes (`backporting_products` in `config/matching.php`, e.g. `wordpress:wordpress`) | `< 7.1.2` also covers patched branch releases such as 7.0.7 or 6.9.10 |
| the CNA ranges added next to NVD ranges when both list release branches, for the branches NVD lists too | NVD does not confirm them |
| the CNA ranges kept next to NVD ranges when neither lists release branches and the two end at different versions | one side has it wrong, often a typo such as `8.85` for `8.8.5` |
| a range from an ADP container rather than the CNA (`adp_sources` in `config/matching.php`, e.g. CISA's vulnrichment) | added after the fact and sometimes wrong, such as module CVEs filed under the platform |
| a CNA entry that calls every version affected by default (`defaultStatus: affected`) | often means "never fixed" or just "not investigated" |

A match is `confidence: "low"` when its range is `version_scope: any` or `confidence: low`. Low confidence matches are only returned with `include_low_confidence=1` and never count towards `recommended_version`. When a record has a high and a low confidence range matching, the high one wins.

NVD configurations with a top-level `AND` ("vulnerable X running on / with Y") don't produce ranges for the platform node. The platform goes into `plugs_into` instead. A platform node is one with no vulnerable matches, or, in older NVD data that marks both sides vulnerable, one with no version info while another node has some.

NVD also returns the CNA's own `affected` version data (the vendor's or advisory database's view), stored with `raw` starting with `cna:`. Neither source is always right: a CPE match is one contiguous range, so a fix shipped on several release branches ("before 5.40.5, from 5.41.0 before 5.42.3") can come out too broad, while the CNA often writes just `< 7.1.2` where NVD lists every backport. Per product, the source whose ranges tell release branches apart (any range with a lower bound) wins:

| NVD per-branch | CNA per-branch | Result |
|---|---|---|
| yes | no | NVD ranges |
| no | yes | CNA ranges |
| yes | yes | NVD ranges, plus the CNA ranges, as low confidence for the branches NVD lists too |
| no | no | CNA ranges when both end at the same version (or the NVD last affected version lies below the CNA fix), else NVD ranges plus the CNA ranges as low confidence |

Further rules:
- A CVE NVD has not analyzed yet (no CPE configuration) gets the CNA ranges alone. The vendor / product comes from the entry's `cpes`, else its `packageName`, else a slug of its names (`Cookie Information` / `WP GDPR Compliance` becomes `cookieinformation` / `wp-gdpr-compliance`).
- CNA ranges that start past their end (a mistyped `4.70` for `4.7.0`) are dropped.
- `version: X, lessThan: X` (WPScan), `version: *` (Wordfence) and `version: n/a` (Patchstack) mean "below X". With `lessThanOrEqual` they mean "X and below", and so does `version: X, lessThanOrEqual: X` (Wordfence).
- Placeholder entries (`n/a`) and entries naming another product leave the CPE ranges alone.
- An entry matches a product by its product, package or module name. If only its vendor name equals the product (a plugin slug that is its author's name), it counts only when it is the single entry matching that way, because the author's Pro plugin may be listed next to it.
- A CPE with an update such as `5.8:beta*` matches only those pre-releases (5.8 betas and release candidates), not 5.8.

After upgrading, run the migrations and re-resolve NVD with `parse:l2 nvd --rerun`. Run `parse:l1 nvd --rerun` first when L1 ran before CNA data was extracted (v2.5.0) or before entries were tagged with the container they come from (needed to tell ADP ranges apart).

### What a check searches

| You pass | Searched | `version` is |
|---|---|---|
| `ecosystem` | only that exact ecosystem (`Ubuntu:24.04:LTS`, `npm`, ...) | the package version of that ecosystem |
| `vendor` only | every range of that vendor and its aliases | as the source states it |
| neither | NVD plus language ecosystems (`npm`, `PyPI`, `Go`, ... see `config/matching.php`) | the upstream version |

**OS packages:** pass the full `ecosystem` of the release you run (find it with [products](#search-products)) and the version your package manager reports, e.g. `ecosystem=Ubuntu:24.04:LTS&version=3.0.13-0ubuntu3.5`. Distro advisories (Debian, Ubuntu, Alpine, Chainguard, ...) are never returned for a check without an ecosystem, their versions can't be compared with an upstream one. Debian and Ubuntu advisories are keyed by source package name, so map a binary package like `libssl3` to its source (`dpkg-query -W -f='${source:Package}'`).

**Applications** (WordPress, nginx, ...): use `vendor` + `product` and the upstream version.

**Packagist:** package names are case insensitive and stored in lowercase, so `Studio-42/elFinder` and `studio-42/elfinder` (as in `composer.lock`) both match. Re-run `parse:l2 osv --rerun` after upgrading to lowercase existing ranges.

**Vendor aliases:** NVD and the CNAs file some products under several vendor names (WooCommerce under both `automattic` and `woocommerce`). `vendor_aliases` in `config/matching.php` groups them. A check naming any vendor of a group searches all of them, and a group counts as one vendor when judging [ambiguity](#ambiguous-products).

### Ambiguous products

Different software can share a product name (`orc` as Apache ORC and as another vendor's `orc`). When neither `vendor` nor `ecosystem` is given and the matches span more than one NVD vendor or more than one language ecosystem, `check` doesn't guess. It returns `ambiguous: true`, `vulnerable: null`, no vulnerabilities, and the `candidates` to pick from. Repeat the request with one of them:

```json
{ "ambiguous": true, "vulnerable": null, "candidates": [{ "vendor": "apache", "ecosystem": null }, { "vendor": "other", "ecosystem": null }] }
```

The same package in NVD and OSV (vendor `lodash` and ecosystem `npm`) is one product, not ambiguous. Ambiguity is only detected between matches, so a product with a single colliding vendor in the data still needs a `vendor` from you. Without a vendor or ecosystem, ranges tied to a language runtime (`plugs_into` of `ruby`, `node.js`, `php`, ...) are skipped; name the vendor to include them. Both lists live in `config/matching.php`.

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

Versions are compared by `App\Services\VersionComparator`. Distro ecosystems use their package manager's own ordering (see below), everything else (NVD, `npm`, `PyPI`, ...) uses one generic ruleset:

- epoch first (`1:2.0` > `9.9`)
- numeric release segment, zero padded (`1.0` == `1.0.0`, `1.9` < `1.10`)
- pre-releases before the release: `dev` < `alpha`/`a` < `beta`/`b` < `pre`/`preview`/`m` < unknown words < `rc`/`c`
- after the release: numbers (`2.30-1`) and `post`/`patch`/`p`/`sp`/`r`
- a lone trailing letter is a post-release (`1.1.1a` > `1.1.1`, openssl style)
- leading `v`, case and `+build` metadata are ignored

### Distro ecosystems

The family is the part of the ecosystem before the first `:` (`Debian:12` is `Debian`), case insensitive.

| Ecosystem family | Ordering |
|---|---|
| `Debian`, `Ubuntu` | dpkg: `[epoch:]upstream[-revision]`, `~` sorts before everything (`1.0~rc1-1` < `1.0-1`), letters sort after the bare release (`1.0rc1-1` > `1.0-1`, the opposite of the generic rule) |
| `Red Hat`, `Rocky Linux`, `AlmaLinux`, `SUSE`, `openSUSE`, `Mageia`, `openEuler`, `Photon OS`, `Azure Linux` | rpmvercmp: `[epoch:]version[-release]`, `~` before the release, `^` after it, numbers newer than letters. A release is only compared when both versions have one |
| `Alpine`, `Alpaquita`, `Chainguard`, `Wolfi`, `MinimOS` | apk: `1.2.3a_rc1-r2`, `_alpha` < `_beta` < `_pre` < `_rc` < release < `_cvs` / `_svn` / `_git` / `_hg` / `_p`, then `-rN` |

Each ordering passes the reference vectors of its package manager (dpkg's `Dpkg_Version.t`, rpm's `rpmvercmp.at`, apk-tools' `version.data`). Maven qualifiers and other ecosystems still use the generic rules.
