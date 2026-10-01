<?php

namespace App\Console\Commands;

use App\Models\Source;
use App\Models\SyncState;
use App\Services\Ingestion\IngestRecordWriter;
use Carbon\Carbon;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Http\Client\Pool;
use Illuminate\Support\Facades\Http;
use InvalidArgumentException;
use Throwable;

#[Signature('ingest:osv-sync {--full : Ignore sync_states and reprocess the entire modified_id.csv} {--workers=1 : number of record downloads to run in parallel}')]
#[Description('Incrementally sync OSV vulnerabilities via modified_id.csv, without re-downloading all.zip')]
class IngestOsvSync extends Command
{

    private const BATCH_SIZE_PER_WORKER = 10;

    private int $processed = 0;

    private int $skipped = 0;

    public function __construct(private IngestRecordWriter $writer)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $workers = filter_var($this->option('workers'), FILTER_VALIDATE_INT);

        if ($workers === false || $workers < 1) {
            throw new InvalidArgumentException('--workers must be a positive integer');
        }

        $source = Source::where('slug', 'osv')->firstOrFail();
        $baseUrl = rtrim($source->ingest_base_url, '/');
        $syncState = SyncState::firstOrCreate(['source_id' => $source->id]);
        $full = (bool) $this->option('full');

        $lastCursor = $full ? null : ($syncState->cursor['last_modified'] ?? null);
        $lastCursorTime = $lastCursor ? Carbon::parse($lastCursor) : null;

        if (! $lastCursorTime) {
            $this->warn('No cursor found — this will process the ENTIRE modified_id.csv (one HTTP request per record). Are you sure? If not, Ctrl+C now and set a cursor first.');
        }

        $csvUrl = "{$baseUrl}/modified_id.csv";
        $this->info("Streaming {$csvUrl}".($lastCursorTime ? " (since {$lastCursorTime})" : ' (full)'));

        $csvPath = storage_path('app/tmp/osv-modified_id.csv');
        @mkdir(dirname($csvPath), recursive: true);

        Http::timeout(120)
            ->withOptions(['sink' => $csvPath])
            ->get($csvUrl)
            ->throw();

        $totalLines = 0;
        $handle = fopen($csvPath, 'r');
        while (fgets($handle) !== false) {
            $totalLines++;
        }
        rewind($handle);

        $bar = $this->output->createProgressBar($totalLines);
        $newestSeen = null;
        $batch = [];

        while (($line = fgets($handle)) !== false) {
            $bar->advance();
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            [$timestamp, $path] = explode(',', $line, 2);
            $rowTime = Carbon::parse($timestamp);

            $newestSeen ??= $timestamp;

            if ($lastCursorTime && $rowTime->lessThanOrEqualTo($lastCursorTime)) {
                break;
            }

            [$ecosystem, $id] = explode('/', $path, 2);
            $batch[] = "{$baseUrl}/{$ecosystem}/{$id}.json";

            if (count($batch) >= $workers * self::BATCH_SIZE_PER_WORKER) {
                $this->fetchBatch($source->id, $batch, $workers);
                $batch = [];
            }
        }

        $this->fetchBatch($source->id, $batch, $workers);

        $bar->finish();
        $this->newLine();
        fclose($handle);
        unlink($csvPath);

        if ($newestSeen) {
            $syncState->update([
                'cursor' => ['last_modified' => $newestSeen],
                'last_synced_at' => now(),
            ]);
        }

        $this->info("Done, {$this->processed} records updated, {$this->skipped} skipped (not found).");

        return self::SUCCESS;
    }

    /**
     * @param  list<string>  $recordUrls
     * @param  positive-int  $workers
     */
    private function fetchBatch(int $sourceId, array $recordUrls, int $workers): void
    {
        if ($recordUrls === []) {
            return;
        }

        $responses = Http::pool(
            fn (Pool $pool) => array_map(fn (string $url) => $pool->as($url)->get($url), $recordUrls),
            concurrency: $workers,
        );

        foreach ($responses as $response) {
            if ($response instanceof Throwable) {
                throw $response;
            }

            if ($response->status() === 404) {
                $this->skipped++;

                continue;
            }
            $response->throw();

            $payload = $response->json();
            if (isset($payload['id'])) {
                $this->writer->upsert($sourceId, $payload['id'], $payload);
                $this->processed++;
            }
        }
    }
}
