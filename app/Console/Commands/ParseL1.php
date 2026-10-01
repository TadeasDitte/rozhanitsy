<?php

namespace App\Console\Commands;

use App\Concerns\RunsParallelWorkers;
use App\Ingestion\ParserResolver;
use App\Ingestion\RecordParsingRunner;
use App\Models\IngestRecord;
use App\Models\Source;
use App\Services\VulnerabilityDataCache;
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
                $this->warn("No parser class found for slug [{$source->slug}], skipping");

                continue;
            }

            if ($partition !== null) {
                (new RecordParsingRunner($parser))->run($source, $this->workerProgressTick(), $partition);

                continue;
            }

            if ($this->option('retry-failed')) {
                $requeued = RecordParsingRunner::requeueFailed($source);

                if ($requeued > 0) {
                    $this->info("Requeued {$requeued} failed records for {$source->slug}");
                }
            }

            if ($this->option('rerun')) {
                $requeued = RecordParsingRunner::requeueProcessed($source);

                if ($requeued > 0) {
                    $this->info("Requeued {$requeued} already-processed records for {$source->slug}");
                }
            }

            $pending = $this->pendingRecords($source)->count();

            if ($pending === 0) {
                $this->info("Nothing pending for {$source->slug}");

                continue;
            }

            $this->info("Parsing {$pending} pending records for {$source->slug}...");

            if ($workers > 1) {
                $allSucceeded = $this->runInWorkers('parse:l1', [$source->slug], $workers, $this->pendingRecords($source)) && $allSucceeded;

                continue;
            }

            $bar = $this->output->createProgressBar($pending);
            $bar->start();

            (new RecordParsingRunner($parser))->run($source, fn () => $bar->advance());

            $bar->finish();
            $this->newLine();
        }

        if ($partition === null) {
            $cache->flush();
        }

        return $allSucceeded ? self::SUCCESS : self::FAILURE;
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
