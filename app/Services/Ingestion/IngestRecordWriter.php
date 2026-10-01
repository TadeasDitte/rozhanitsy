<?php

namespace App\Services\Ingestion;

use App\Models\IngestRecord;

class IngestRecordWriter
{
    /**
     * @param  array<string, mixed>  $payload
     */
    public function upsert(int $sourceId, string $externalId, array $payload): IngestRecord
    {
        $existing = IngestRecord::where('source_id', $sourceId)
            ->where('external_id', $externalId)
            ->first();

        if ($existing && $this->unchanged($existing->raw_payload, $payload)) {
            $existing->touch('fetched_at');

            return $existing;
        }

        return IngestRecord::updateOrCreate(
            ['source_id' => $sourceId, 'external_id' => $externalId],
            [
                'raw_payload' => $payload,
                'fetched_at' => now(),
                'processing_status' => 'pending',
                'processing_error' => null,
            ]
        );
    }

    /**
     * @param  array<string, mixed>  $existing
     * @param  array<string, mixed>  $incoming
     */
    private function unchanged(array $existing, array $incoming): bool
    {
        return $this->normalize($existing) === $this->normalize($incoming);
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private function normalize(array $data): string
    {
        $sort = function (&$arr) use (&$sort) {
            if (is_array($arr)) {
                ksort($arr);
                foreach ($arr as &$v) {
                    if (is_array($v)) {
                        $sort($v);
                    }
                }
            }
        };
        $sort($data);

        return json_encode($data, JSON_THROW_ON_ERROR);
    }
}
