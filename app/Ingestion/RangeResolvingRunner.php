<?php

namespace App\Ingestion;

use App\Ingestion\Parsers\RangeParser;
use App\Models\ParsedRecord;
use App\Models\Source;
use App\Models\VersionRange;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use Throwable;

final class RangeResolvingRunner
{
    /**
     * Rows per insert statement. A statement can bind at most 65535 parameters
     * (PostgreSQL), and a range has 17 columns, so one huge record cannot go in one.
     * Rows are also built one batch at a time: a record can have hundreds of
     * thousands of ranges and a full set of row arrays does not fit in memory.
     */
    private const int INSERT_CHUNK_SIZE = 1000;

    public function __construct(
        private readonly RangeParser $parser,
        private readonly int $formatId,
    ) {}

    public function run(Source $source, ?callable $onEach = null, ?Partition $partition = null): void
    {
        ParsedRecord::query()
            ->when($partition !== null, fn ($query) => $partition->apply($query))
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
            unset($rawRanges);

            DB::transaction(function () use ($record, $ranges) {
                VersionRange::where('parsed_record_id', $record->id)->delete();

                $recordId = $record->id;
                $timestamp = now()->toDateTimeString();

                foreach (array_chunk($ranges, self::INSERT_CHUNK_SIZE) as $batch) {
                    VersionRange::insert(array_map(fn (VersionRangeData $range): array => [
                        'parsed_record_id' => $recordId,
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
                        'confidence' => $range->confidence,
                        'plugs_into' => $range->plugsInto,
                        'raw' => $range->raw,
                        'created_at' => $timestamp,
                        'updated_at' => $timestamp,
                    ], $batch));
                }

                $record->update(['resolved_at' => now()]);
            });
        } catch (Throwable $e) {
            Context::scope(fn () => report($e), [
                'source_id' => $record->source_id,
                'parsed_record_id' => $record->id,
                'external_id' => $record->external_id,
            ]);
        }
    }
}
