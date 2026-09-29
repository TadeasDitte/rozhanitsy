<?php

namespace App\Console\Commands;

use App\Ingestion\ParserResolver;
use App\Ingestion\RangeResolvingRunner;
use App\Models\ParsedRecord;
use App\Models\Source;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;

#[Signature('parse:l2 {source? : source slug, defaults to all} {--rerun : re-resolve already-resolved records}')]
#[Description('Run Layer 2 resolution: expand parsed_records.raw_ranges into version_ranges')]
final class ParseL2 extends Command
{
    public function handle(ParserResolver $resolver): int
    {
        $sources = $this->argument('source')
            ? Source::where('slug', $this->argument('source'))->get()
            : Source::all();

        foreach ($sources as $source) {
            $parser = $resolver->rangeParser($source->slug);

            if ($parser === null) {
                $this->warn("No range parser class found for slug [{$source->slug}], skipping");

                continue;
            }

            $formatId = $resolver->formatId($source->slug);

            if ($formatId === null) {
                $this->warn("No format row for slug [{$source->slug}], run FormatSeeder. Skipping");

                continue;
            }

            if ($this->option('rerun')) {
                $reset = ParsedRecord::where('source_id', $source->id)
                    ->whereNotNull('resolved_at')
                    ->update(['resolved_at' => null]);

                if ($reset > 0) {
                    $this->info("Reset {$reset} resolved records for {$source->slug}");
                }
            }

            $pending = ParsedRecord::where('source_id', $source->id)
                ->whereNull('resolved_at')
                ->count();

            if ($pending === 0) {
                $this->info("Nothing to resolve for {$source->slug}");

                continue;
            }

            $this->info("Resolving {$pending} parsed records for {$source->slug}...");
            $bar = $this->output->createProgressBar($pending);
            $bar->start();

            (new RangeResolvingRunner($parser, $formatId))->run($source, fn () => $bar->advance());

            $bar->finish();
            $this->newLine();
        }

        return self::SUCCESS;
    }
}
