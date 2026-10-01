<?php

namespace App\Ingestion\Parsers;

use App\Ingestion\ParsedRecordData;

interface SourceRecordParser
{
    /**
     * @param  array<string, mixed>  $rawPayload  IngestRecord::raw_payload for one row
     * @return ParsedRecordData|null null means "intentionally skip", not a failure
     */
    public function parseOne(array $rawPayload): ?ParsedRecordData;
}
