<?php

namespace App\Ingestion;

use App\Ingestion\Parsers\SourceRecordParser;
use App\Models\IngestRecord;
use App\Models\ParsedRecord;
use App\Models\Source;
use Carbon\CarbonInterface;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

final class RecordParsingRunner
{
    public function __construct(private readonly SourceRecordParser $parser) {}

    public function run(Source $source, ?callable $onEach = null, ?Partition $partition = null): void
    {
        IngestRecord::query()
            ->when($partition !== null, fn ($query) => $partition->apply($query))
            ->where('source_id', $source->id)
            ->where('processing_status', 'pending')
            ->chunkById(500, function ($records) use ($onEach) {
                foreach ($records as $record) {
                    $this->processOne($record);

                    if ($onEach !== null) {
                        $onEach();
                    }
                }
            });
    }

    public static function requeueFailed(Source $source): int
    {
        return IngestRecord::where('source_id', $source->id)
            ->where('processing_status', 'failed')
            ->update(['processing_status' => 'pending', 'processing_error' => null]);
    }

    public static function requeueProcessed(Source $source): int
    {
        return IngestRecord::where('source_id', $source->id)
            ->whereIn('processing_status', ['processed', 'skipped'])
            ->update(['processing_status' => 'pending', 'processed_at' => null, 'processing_error' => null]);
    }

    public static function failedSince(Source $source, CarbonInterface $since): int
    {
        return IngestRecord::where('source_id', $source->id)
            ->where('processing_status', 'failed')
            ->where('processed_at', '>=', $since->copy()->startOfSecond())
            ->count();
    }

    public function processOne(IngestRecord $ingestRecord): ?ParsedRecord
    {
        try {
            $parsed = $this->parser->parseOne($ingestRecord->raw_payload);

            if ($parsed === null) {
                $ingestRecord->update(['processing_status' => 'skipped', 'processed_at' => now()]);

                return null;
            }

            return DB::transaction(function () use ($ingestRecord, $parsed) {
                $parsedRecord = ParsedRecord::updateOrCreate(
                    ['ingest_record_id' => $ingestRecord->id],
                    [
                        'source_id' => $ingestRecord->source_id,
                        'external_id' => $parsed->externalId,
                        'cvss_score' => $parsed->cvssScore,
                        'cvss_vector' => $parsed->cvssVector,
                        'cvss_version' => $parsed->cvssVersion,
                        'cvss_severity' => $parsed->cvssSeverity,
                        'description' => $parsed->description,
                        'published_at' => $parsed->publishedAt,
                        'last_modified_at' => $parsed->lastModifiedAt,
                        'weaknesses' => $parsed->weaknesses,
                        'references' => $parsed->references,
                        'status' => $parsed->status,
                        'known_exploited' => $parsed->knownExploited,
                        'raw_ranges' => $parsed->rawRanges,
                        'resolved_at' => null,
                    ]
                );

                $parsedRecord->aliases()->delete();
                $parsedRecord->aliases()->createMany(
                    array_map(fn (string $alias) => ['alias' => $alias], array_values(array_unique($parsed->aliases)))
                );

                $ingestRecord->update(['processing_status' => 'processed', 'processed_at' => now()]);

                return $parsedRecord;
            });
        } catch (Throwable $e) {
            $ingestRecord->update([
                'processing_status' => 'failed',
                'processing_error' => $e->getMessage(),
                'processed_at' => now(),
            ]);

            Log::warning('Failed to parse ingest record', [
                'source_id' => $ingestRecord->source_id,
                'ingest_record_id' => $ingestRecord->id,
                'external_id' => $ingestRecord->external_id,
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }
}
