# Data Ingest

## NVD

https://nvd.nist.gov/developers/vulnerabilities

### Bulk Ingest

startIndex optional

    {offset}

This parameter specifies the index of the first CVE to be returned in the response data. The index is zero-based, meaning the first CVE is at index zero.

The CVE API returns four primary objects in the response body that are used for pagination: resultsPerPage, startIndex, totalResults, and vulnerabilities. totalResults indicates the total number of CVE records that match the request parameters. If the value of totalResults is greater than the value of resultsPerPage, there are more records than could be returned by a single API response and additional requests must update the startIndex to get the remaining records.

The best, most efficient, practice for keeping up to date with the NVD is to use the date range parameters to request only the CVEs that have been modified since your last request.
Request 20 CVE records, beginning at index 0 and ending at index 19

https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=20&startIndex=0

Request the CVE records, beginning at index 20 and ending at index 39

https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=20&startIndex=20

## OSV

https://google.github.io/osv.dev/data/
https://ossf.github.io/osv-schema

### Bulk Ingest

Full database download

This bucket contains a zip file with all vulnerabilities across all ecosystems (including withdrawn records) at gs://osv-vulnerabilities/all.zip. This is the easiest way to download the entire OSV database.

Per-ecosystem downloads

Individual vulnerability records can be found at gs://osv-vulnerabilities/<ECOSYSTEM>/<ID>.json. A zip containing all vulnerabilities for each ecosystem is available at gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip. Vulnerabilities without an ecosystem (typically withdrawn ones) are exported to the gs://osv-vulnerabilities/[EMPTY]/ directory.

For future use: https://osv-vulnerabilities.storage.googleapis.com/
