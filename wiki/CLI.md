# CLI

## Ingest

All ingest related commands start with `php artisan ingest:`
This is the only command that can talk to the outside world and the Interwebs

### NVD

The only command needed here is `php artisan ingest:nvd`

On the first run or with the `--full` flag it takes all data that NVD has to offer, otherwise it only takes data that changed since the last ingest

### OSV

As of now there is `php artisan ingest:osv` 
This downloads all.zip, from any specified ecosystem. Reffer to [this](https://google.github.io/osv.dev/data/#ecosystem-naming) and [this](https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt)
If left unspecified it downloads the root all.zip

And `php artisan ingest:osv-sync`
checks modified_id.csv and downloads and updates only the modified entries since the last ingest
Add `--workers=N` to download N records concurrently

## Parse

`php artisan parse:l1` is the only parser as of now and should be ran after any ingest
It passes raw data from sources through source specific parsers into a parsed_records table

`--retry-failed` flag does what it says it does

`php artisan parse:fast` runs every layer per record instead of per layer: each pending ingest record goes through L1 (parsed_records + aliases) and straight into L2 (version_ranges) before the next one is picked up.
Afterwards it also resolves any parsed_records still left unresolved from earlier L1-only runs.
Takes the same `--retry-failed` and `--rerun` flags as `parse:l1`

## Parallelism

`parse:l1`, `parse:l2` and `parse:fast` take `--workers=N` (default 1). The command does the requeueing itself, then splits the pending records into N contiguous id ranges of roughly equal size and runs each range in its own `php artisan` child process, while showing one combined progress bar. Each worker uses its own DB connection, so keep N below your Postgres `max_connections`.
The `--partition=FIRST_ID-LAST_ID` option that the workers receive can also be passed by hand, for example to split a run across machines.

`ingest:osv-sync --workers=N` downloads up to N record JSONs at once instead of one after another.
