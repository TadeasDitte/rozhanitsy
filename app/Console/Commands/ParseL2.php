<?php

namespace App\Console\Commands;

use App\Concerns\RunsParallelWorkers;
use App\Ingestion\ParserResolver;
use App\Ingestion\RangeResolvingRunner;
use App\Models\ParsedRecord;
use App\Models\Source;
use App\Services\VulnerabilityDataCache;
use Carbon\CarbonInterface;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;

#[Signature('parse:l2 {source? : source slug, defaults to all} {--rerun : re-resolve already-resolved records} {--workers=1 : number of parallel worker processes} {--partition= : internal, set by --workers: only process records with ids in FIRST_ID-LAST_ID}')]
#[Description('Run Layer 2 resolution: expand parsed_records.raw_ranges into version_ranges')]
final class ParseL2 extends Command
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
            $parser = $resolver->rangeParser($source->slug);

            if ($parser === null) {
                $this->logWarning("No range parser class found for slug [{$source->slug}], skipping", ['source' => $source->slug]);

                continue;
            }

            $formatId = $resolver->formatId($source->slug);

            if ($formatId === null) {
                $this->logWarning("No format row for slug [{$source->slug}], run FormatSeeder. Skipping", ['source' => $source->slug]);

                continue;
            }

            if ($partition !== null) {
                (new RangeResolvingRunner($parser, $formatId))->run($source, $this->workerProgressTick(), $partition);

                continue;
            }

            if ($this->option('rerun')) {
                $reset = ParsedRecord::where('source_id', $source->id)
                    ->whereNotNull('resolved_at')
                    ->update(['resolved_at' => null]);

                if ($reset > 0) {
                    $this->logInfo("Reset {$reset} resolved records for {$source->slug}", ['source' => $source->slug, 'reset' => $reset]);
                }
            }

            $pending = $this->unresolvedRecords($source)->count();

            if ($pending === 0) {
                $this->logInfo("Nothing to resolve for {$source->slug}", ['source' => $source->slug]);

                continue;
            }

            $this->logInfo("Resolving {$pending} parsed records for {$source->slug}...", ['source' => $source->slug, 'pending' => $pending, 'workers' => $workers]);
            $startedAt = now();

            if ($workers > 1) {
                $allSucceeded = $this->runInWorkers('parse:l2', [$source->slug], $workers, $this->unresolvedRecords($source)) && $allSucceeded;
            } else {
                $bar = $this->output->createProgressBar($pending);
                $bar->start();

                (new RangeResolvingRunner($parser, $formatId))->run($source, fn () => $bar->advance());

                $bar->finish();
                $this->newLine();
            }

            $this->logResolveSummary($source, $pending, $startedAt);
        }

        if ($partition === null) {
            $cache->flush();
        }

        return $allSucceeded ? self::SUCCESS : self::FAILURE;
    }

    private function logResolveSummary(Source $source, int $pending, CarbonInterface $startedAt): void
    {
        $unresolved = $this->unresolvedRecords($source)->count();
        $durationSeconds = round($startedAt->diffInSeconds(now()), 1);

        $this->logInfo("Resolved {$pending} records for {$source->slug} in {$durationSeconds}s", [
            'source' => $source->slug,
            'records' => $pending,
            'unresolved' => $unresolved,
            'duration_seconds' => $durationSeconds,
        ]);

        if ($unresolved > 0) {
            $this->logWarning("{$unresolved} records could not be resolved for {$source->slug}, see the reported exceptions", [
                'source' => $source->slug,
                'unresolved' => $unresolved,
            ]);
        }
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
