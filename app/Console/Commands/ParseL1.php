<?php

namespace App\Console\Commands;

use App\Concerns\RunsParallelWorkers;
use App\Ingestion\ParserResolver;
use App\Ingestion\RecordParsingRunner;
use App\Models\IngestRecord;
use App\Models\Source;
use App\Services\VulnerabilityDataCache;
use Carbon\CarbonInterface;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;

#[Signature('parse:l1 {source? : source slug, defaults to all} {--retry-failed : requeue failed records before parsing} {--rerun : requeue already-processed records so they are parsed again} {--workers=1 : number of parallel worker processes} {--partition= : internal, set by --workers: only process records with ids in FIRST_ID-LAST_ID}')]
#[Description('Run Layer 1 parsing against pending ingest_records')]
final class ParseL1 extends Command
{
    use RunsParallelWorkers;

    public function handle(ParserResolver $resolver, VulnerabilityDataCache $cache): int
    {
        $partition = $this->partition();
        $workers = $partition === null ? $this->workerCount() : 1;
        $allSucceeded = true;

        $sources = $this->argument('source')
            ? Source::where('slug', $this->argument('source'))->get()
            : Source::all();

        foreach ($sources as $source) {
            $parser = $resolver->recordParser($source->slug);

            if ($parser === null) {
                $this->logWarning("No parser class found for slug [{$source->slug}], skipping", ['source' => $source->slug]);

                continue;
            }

            if ($partition !== null) {
                (new RecordParsingRunner($parser))->run($source, $this->workerProgressTick(), $partition);

                continue;
            }

            if ($this->option('retry-failed')) {
                $requeued = RecordParsingRunner::requeueFailed($source);

                if ($requeued > 0) {
                    $this->logInfo("Requeued {$requeued} failed records for {$source->slug}", ['source' => $source->slug, 'requeued' => $requeued]);
                }
            }

            if ($this->option('rerun')) {
                $requeued = RecordParsingRunner::requeueProcessed($source);

                if ($requeued > 0) {
                    $this->logInfo("Requeued {$requeued} already-processed records for {$source->slug}", ['source' => $source->slug, 'requeued' => $requeued]);
                }
            }

            $pending = $this->pendingRecords($source)->count();

            if ($pending === 0) {
                $this->logInfo("Nothing pending for {$source->slug}", ['source' => $source->slug]);

                continue;
            }

            $this->logInfo("Parsing {$pending} pending records for {$source->slug}...", ['source' => $source->slug, 'pending' => $pending, 'workers' => $workers]);
            $startedAt = now();

            if ($workers > 1) {
                $allSucceeded = $this->runInWorkers('parse:l1', [$source->slug], $workers, $this->pendingRecords($source)) && $allSucceeded;
            } else {
                $bar = $this->output->createProgressBar($pending);
                $bar->start();

                (new RecordParsingRunner($parser))->run($source, fn () => $bar->advance());

                $bar->finish();
                $this->newLine();
            }

            $this->logParseSummary($source, $pending, $startedAt);
        }

        if ($partition === null) {
            $cache->flush();
        }

        return $allSucceeded ? self::SUCCESS : self::FAILURE;
    }

    private function logParseSummary(Source $source, int $pending, CarbonInterface $startedAt): void
    {
        $failed = RecordParsingRunner::failedSince($source, $startedAt);
        $durationSeconds = round($startedAt->diffInSeconds(now()), 1);

        $this->logInfo("Parsed {$pending} records for {$source->slug} in {$durationSeconds}s", [
            'source' => $source->slug,
            'records' => $pending,
            'failed' => $failed,
            'duration_seconds' => $durationSeconds,
        ]);

        if ($failed > 0) {
            $this->logWarning("{$failed} records failed to parse for {$source->slug}, requeue them with --retry-failed", [
                'source' => $source->slug,
                'failed' => $failed,
            ]);
        }
    }

    /**
     * @return Builder<IngestRecord>
     */
    private function pendingRecords(Source $source): Builder
    {
        return IngestRecord::where('source_id', $source->id)
            ->where('processing_status', 'pending');
    }
}
