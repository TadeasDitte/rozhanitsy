<?php

namespace App\Console\Commands;

use App\Concerns\LogsCommandOutput;
use App\Models\Source;
use App\Models\SyncState;
use App\Services\Ingestion\IngestRecordWriter;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;
use ZipArchive;

#[Signature('ingest:osv {ecosystem=All}')]
#[Description('Pull an OSV ecosystem bulk export into ingest_records')]
class IngestOsv extends Command
{
    use LogsCommandOutput;

    public function __construct(private IngestRecordWriter $writer)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $ecosystem = $this->argument('ecosystem');
        $source = Source::where('slug', 'osv')->firstOrFail();

        $baseUrl = rtrim($source->ingest_base_url, '/');

        $url = $ecosystem === 'All'
            ? "{$baseUrl}/all.zip"
            : "{$baseUrl}/{$ecosystem}/all.zip";

        $slug = $ecosystem === 'All' ? 'all' : $ecosystem;

        $this->logInfo("Downloading {$url}", ['url' => $url, 'ecosystem' => $ecosystem]);
        $startedAt = now();
        $zipPath = storage_path("app/tmp/osv-{$slug}.zip");
        @mkdir(dirname($zipPath), recursive: true);

        Http::timeout(600)
            ->withOptions(['sink' => $zipPath])
            ->get($url)
            ->throw();

        $extractPath = storage_path("app/tmp/osv-{$slug}");
        $zip = new ZipArchive;
        $zip->open($zipPath);
        $zip->extractTo($extractPath);
        $zip->close();

        $files = glob("{$extractPath}/*.json") ?: [];
        $bar = $this->output->createProgressBar(count($files));

        $written = 0;
        foreach ($files as $file) {
            $payload = File::json($file);
            if (isset($payload['id'])) {
                $this->writer->upsert($source->id, $payload['id'], $payload);
                $written++;
            }
            $bar->advance();
        }
        $bar->finish();
        $this->newLine();

        unlink($zipPath);
        array_map('unlink', $files);
        rmdir($extractPath);

        SyncState::updateOrCreate(
            ['source_id' => $source->id],
            [
                'cursor' => ['last_modified' => now()->toIso8601ZuluString()],
                'last_synced_at' => now(),
            ]
        );

        $durationSeconds = round($startedAt->diffInSeconds(now()), 1);
        $this->logInfo("Done, {$written} records written in {$durationSeconds}s.", ['ecosystem' => $ecosystem, 'records' => $written, 'files' => count($files), 'duration_seconds' => $durationSeconds]);

        return self::SUCCESS;
    }
}
