<?php

namespace App\Ingestion;

use App\Ingestion\Parsers\RangeParser;
use App\Models\ParsedRecord;
use App\Models\Source;
use App\Models\VersionRange;
use Illuminate\Support\Facades\DB;
use Throwable;

final class RangeResolvingRunner
{
    public function __construct(
        private readonly RangeParser $parser,
        private readonly int $formatId,
    ) {}

    public function run(Source $source, ?callable $onEach = null): void
    {
        ParsedRecord::query()
            ->where('source_id', $source->id)
            ->whereNull('resolved_at')
            ->chunkById(500, function ($records) use ($onEach) {
                foreach ($records as $record) {
                    $this->processOne($record);

                    if ($onEach !== null) {
                        $onEach();
                    }
                }
            });
    }

    public function processOne(ParsedRecord $record): void
    {
        try {
            /** @var array<int, array<string, mixed>> $rawRanges */
            $rawRanges = (array) ($record->raw_ranges ?? []);
            $ranges = $this->parser->parse($rawRanges);

            DB::transaction(function () use ($record, $ranges) {
                VersionRange::where('parsed_record_id', $record->id)->delete();

                if ($ranges !== []) {
                    VersionRange::insert(array_map(fn (VersionRangeData $range): array => [
                        'parsed_record_id' => $record->id,
                        'format_id' => $this->formatId,
                        'type' => $range->type,
                        'ecosystem' => $range->ecosystem,
                        'package_manager' => $range->packageManager,
                        'vendor' => $range->vendor,
                        'product' => $range->product,
                        'version_incl_start' => $range->versionInclStart,
                        'version_excl_start' => $range->versionExclStart,
                        'version_incl_end' => $range->versionInclEnd,
                        'version_excl_end' => $range->versionExclEnd,
                        'version_scope' => $range->versionScope,
                        'plugs_into' => $range->plugsInto,
                        'raw' => $range->raw,
                        'created_at' => now(),
                        'updated_at' => now(),
                    ], $ranges));
                }

                $record->update(['resolved_at' => now()]);
            });
        } catch (Throwable $e) {
            report($e);
        }
    }
}
