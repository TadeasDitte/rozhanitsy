<?php

namespace App\Console\Commands;

use App\Concerns\RunsParallelWorkers;
use App\Ingestion\ParserResolver;
use App\Ingestion\PipelineRunner;
use App\Ingestion\RangeResolvingRunner;
use App\Ingestion\RecordParsingRunner;
use App\Models\IngestRecord;
use App\Models\ParsedRecord;
use App\Models\Source;
use App\Services\VulnerabilityDataCache;
use Carbon\CarbonInterface;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;

#[Signature('parse:fast {source? : source slug, defaults to all} {--retry-failed : requeue failed records before parsing} {--rerun : requeue already-processed records so they are parsed again} {--workers=1 : number of parallel worker processes} {--partition= : internal, set by --workers: only process records with ids in FIRST_ID-LAST_ID}')]
#[Description('Run every parse layer per record: each pending ingest_record goes through L1 and L2 before the next one')]
final class ParseFast extends Command
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
            $recordParser = $resolver->recordParser($source->slug);

            if ($recordParser === null) {
                $this->logWarning("No parser class found for slug [{$source->slug}], skipping", ['source' => $source->slug]);

                continue;
            }

            $rangeResolving = $this->rangeResolvingRunner($resolver, $source);

            if ($partition !== null) {
                (new PipelineRunner(new RecordParsingRunner($recordParser), $rangeResolving))
                    ->run($source, $this->workerProgressTick(), $partition);

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

            if ($pending > 0) {
                $this->logInfo("Parsing {$pending} pending records for {$source->slug}...", ['source' => $source->slug, 'pending' => $pending, 'workers' => $workers]);
                $startedAt = now();

                if ($workers > 1) {
                    $allSucceeded = $this->runInWorkers('parse:fast', [$source->slug], $workers, $this->pendingRecords($source)) && $allSucceeded;
                } else {
                    $bar = $this->output->createProgressBar($pending);
                    $bar->start();

                    (new PipelineRunner(new RecordParsingRunner($recordParser), $rangeResolving))
                        ->run($source, fn () => $bar->advance());

                    $bar->finish();
                    $this->newLine();
                }

                $this->logParseSummary($source, $pending, $startedAt);
            } else {
                $this->logInfo("Nothing pending for {$source->slug}", ['source' => $source->slug]);
            }

            if ($rangeResolving !== null) {
                $allSucceeded = $this->resolveLeftovers($rangeResolving, $source, $workers) && $allSucceeded;
            }
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

    private function rangeResolvingRunner(ParserResolver $resolver, Source $source): ?RangeResolvingRunner
    {
        $rangeParser = $resolver->rangeParser($source->slug);

        if ($rangeParser === null) {
            $this->logWarning("No range parser class found for slug [{$source->slug}], running L1 only", ['source' => $source->slug]);

            return null;
        }

        $formatId = $resolver->formatId($source->slug);

        if ($formatId === null) {
            $this->logWarning("No format row for slug [{$source->slug}], run FormatSeeder. Running L1 only", ['source' => $source->slug]);

            return null;
        }

        return new RangeResolvingRunner($rangeParser, $formatId);
    }

    /**
     * Picks up parsed records that were left unresolved by earlier L1-only runs or failed L2 attempts.
     *
     * @return bool whether every worker exited successfully
     */
    private function resolveLeftovers(RangeResolvingRunner $rangeResolving, Source $source, int $workers): bool
    {
        $unresolved = $this->unresolvedRecords($source)->count();

        if ($unresolved === 0) {
            return true;
        }

        $this->logInfo("Resolving {$unresolved} leftover parsed records for {$source->slug}...", ['source' => $source->slug, 'unresolved' => $unresolved]);

        if ($workers > 1) {
            return $this->runInWorkers('parse:l2', [$source->slug], $workers, $this->unresolvedRecords($source));
        }

        $bar = $this->output->createProgressBar($unresolved);
        $bar->start();

        $rangeResolving->run($source, fn () => $bar->advance());

        $bar->finish();
        $this->newLine();

        return true;
    }

    /**
     * @return Builder<ParsedRecord>
     */
    private function unresolvedRecords(Source $source): Builder
    {
        return ParsedRecord::where('source_id', $source->id)
            ->whereNull('resolved_at');
    }
}
