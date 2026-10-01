<?php

namespace App\Ingestion;

use App\Models\IngestRecord;
use App\Models\Source;

final class PipelineRunner
{
    public function __construct(
        private readonly RecordParsingRunner $recordParsing,
        private readonly ?RangeResolvingRunner $rangeResolving,
    ) {}

    public function run(Source $source, ?callable $onEach = null, ?Partition $partition = null): void
    {
        IngestRecord::query()
            ->when($partition !== null, fn ($query) => $partition->apply($query))
            ->where('source_id', $source->id)
            ->where('processing_status', 'pending')
            ->chunkById(500, function ($records) use ($onEach) {
                foreach ($records as $record) {
                    $parsedRecord = $this->recordParsing->processOne($record);

                    if ($parsedRecord !== null && $this->rangeResolving !== null) {
                        $this->rangeResolving->processOne($parsedRecord);
                    }

                    if ($onEach !== null) {
                        $onEach();
                    }
                }
            });
    }
}
