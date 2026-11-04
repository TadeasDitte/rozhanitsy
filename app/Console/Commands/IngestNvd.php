<?php

namespace App\Console\Commands;

use App\Concerns\LogsCommandOutput;
use App\Models\Source;
use App\Models\SyncState;
use App\Services\Ingestion\IngestRecordWriter;
use Carbon\Carbon;
use Carbon\CarbonInterface;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;

#[Signature('ingest:nvd {--full : Ignore sync_states and pull every CVE NVD has}')]
#[Description('Pull CVEs from NVD API 2.0 into ingest_records')]
class IngestNvd extends Command
{
    use LogsCommandOutput;

    private const PAGE_SIZE = 2000;

    private const MAX_DATE_RANGE_DAYS = 120;

    private const RATE_LIMIT_DELAY_WITH_KEY = 0.6;

    private const RATE_LIMIT_DELAY_NO_KEY = 6.0;

    public function __construct(private IngestRecordWriter $writer)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $source = Source::where('slug', 'nvd')->firstOrFail();
        $syncState = SyncState::firstOrCreate(['source_id' => $source->id]);
        $startedAt = now();
        $processed = 0;

        foreach ($this->resolveWindows($syncState, (bool) $this->option('full'), Carbon::now('UTC')) as $window) {
            $processed += $this->ingestWindow($source, $window['start'], $window['end']);

            $syncState->update([
                'cursor' => ['last_mod_end_date' => $this->formatDate($window['end'])],
                'last_synced_at' => now(),
            ]);
        }

        $durationSeconds = round($startedAt->diffInSeconds(now()), 1);
        $this->logInfo("Done, {$processed} records written in {$durationSeconds}s.", ['records' => $processed, 'duration_seconds' => $durationSeconds]);

        return self::SUCCESS;
    }

    private function ingestWindow(Source $source, ?CarbonInterface $start, CarbonInterface $end): int
    {
        $apiKey = config('services.nvd.api_key');
        $dateRange = [];

        if ($start === null) {
            $this->logInfo('Syncing full NVD catalog', ['has_api_key' => (bool) $apiKey]);
        } else {
            $windowStart = $this->formatDate($start);
            $windowEnd = $this->formatDate($end);
            $dateRange = ['lastModStartDate' => $windowStart, 'lastModEndDate' => $windowEnd];
            $this->logInfo("Syncing NVD {$windowStart} → {$windowEnd}", ['window_start' => $windowStart, 'window_end' => $windowEnd, 'has_api_key' => (bool) $apiKey]);
        }

        $startIndex = 0;
        $total = null;
        $processed = 0;
        $bar = null;

        do {
            $response = Http::withHeaders(array_filter(['apiKey' => $apiKey]))
                ->timeout(60)
                ->retry(3, 2000)
                ->get(rtrim($source->ingest_base_url, '/'), [
                    ...$dateRange,
                    'resultsPerPage' => self::PAGE_SIZE,
                    'startIndex' => $startIndex,
                ]);

            if ($response->status() === 429) {
                $this->logWarning('Rate limited — backing off 30s', ['start_index' => $startIndex]);
                Sleep::sleep(30);

                continue;
            }
            $response->throw();

            $data = $response->json();
            $total ??= $data['totalResults'];

            if ($bar === null) {
                $bar = $this->output->createProgressBar($total);
            }

            foreach ($data['vulnerabilities'] ?? [] as $vuln) {
                $this->writer->upsert($source->id, $vuln['cve']['id'], $vuln);
                $processed++;
                $bar->advance();
            }

            $startIndex += self::PAGE_SIZE;
            $this->throttle((bool) $apiKey);
        } while ($startIndex < $total);

        $bar?->finish();
        $this->newLine();

        return $processed;
    }

    private function throttle(bool $hasApiKey): void
    {
        $delaySeconds = $hasApiKey
            ? self::RATE_LIMIT_DELAY_WITH_KEY
            : self::RATE_LIMIT_DELAY_NO_KEY;

        Sleep::usleep((int) ($delaySeconds * 1_000_000));
    }

    /**
     * @return list<array{start: CarbonInterface|null, end: CarbonInterface}>
     */
    private function resolveWindows(SyncState $syncState, bool $full, CarbonInterface $now): array
    {
        $lastCursor = $syncState->cursor['last_mod_end_date'] ?? null;

        if ($full || ! $lastCursor) {
            return [['start' => null, 'end' => $now]];
        }

        $windows = [];
        $start = Carbon::parse($lastCursor)->utc();

        while ($start->lessThan($now)) {
            $end = $start->copy()->addDays(self::MAX_DATE_RANGE_DAYS)->min($now);
            $windows[] = ['start' => $start, 'end' => $end];
            $start = $end;
        }

        return $windows;
    }

    private function formatDate(CarbonInterface $date): string
    {
        return $date->format('Y-m-d\TH:i:s.000\Z');
    }
}
