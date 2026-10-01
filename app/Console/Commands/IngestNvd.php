<?php

namespace App\Console\Commands;

use App\Concerns\LogsCommandOutput;
use App\Models\Source;
use App\Models\SyncState;
use App\Services\Ingestion\IngestRecordWriter;
use Carbon\Carbon;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

#[Signature('ingest:nvd {--full : Ignore sync_states and pull the full 120-day window}')]
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
        $baseUrl = rtrim($source->ingest_base_url, '/');
        $syncState = SyncState::firstOrCreate(['source_id' => $source->id]);
        $apiKey = config('services.nvd.api_key');

        [$start, $end] = $this->resolveWindow($syncState, (bool) $this->option('full'));
        $this->logInfo("Syncing NVD {$start} → {$end}", ['window_start' => $start, 'window_end' => $end, 'has_api_key' => (bool) $apiKey]);
        $startedAt = now();

        $startIndex = 0;
        $total = null;
        $processed = 0;
        $bar = null;

        do {
            $response = Http::withHeaders(array_filter(['apiKey' => $apiKey]))
                ->timeout(60)
                ->retry(3, 2000)
                ->get($baseUrl, [
                    'lastModStartDate' => $start,
                    'lastModEndDate' => $end,
                    'resultsPerPage' => self::PAGE_SIZE,
                    'startIndex' => $startIndex,
                ]);

            if ($response->status() === 429) {
                $this->logWarning('Rate limited — backing off 30s', ['start_index' => $startIndex]);
                sleep(30);

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

        $syncState->update([
            'cursor' => ['last_mod_end_date' => $end],
            'last_synced_at' => now(),
        ]);

        $durationSeconds = round($startedAt->diffInSeconds(now()), 1);
        $this->logInfo("Done, {$processed} records written in {$durationSeconds}s.", ['records' => $processed, 'total_results' => $total, 'duration_seconds' => $durationSeconds]);

        return self::SUCCESS;
    }

    private function throttle(bool $hasApiKey): void
    {
        $delaySeconds = $hasApiKey
            ? self::RATE_LIMIT_DELAY_WITH_KEY
            : self::RATE_LIMIT_DELAY_NO_KEY;

        usleep((int) ($delaySeconds * 1_000_000));
    }

    /**
     * @return array{string, string}
     */
    private function resolveWindow(SyncState $syncState, bool $full): array
    {
        $end = Carbon::now('UTC');
        $lastCursor = $syncState->cursor['last_mod_end_date'] ?? null;

        if ($full || ! $lastCursor) {
            $start = $end->copy()->subDays(self::MAX_DATE_RANGE_DAYS);
        } else {
            $start = Carbon::parse($lastCursor);
            if ($start->diffInDays($end) > self::MAX_DATE_RANGE_DAYS) {
                $start = $end->copy()->subDays(self::MAX_DATE_RANGE_DAYS);
            }
        }

        return [$start->format('Y-m-d\TH:i:s.000\Z'), $end->format('Y-m-d\TH:i:s.000\Z')];
    }
}
