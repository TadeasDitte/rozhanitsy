<?php

namespace App\Models;

use Database\Factories\IngestRecordFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $source_id
 * @property string $external_id
 * @property array<string, mixed> $raw_payload
 * @property Carbon $fetched_at
 * @property Carbon|null $processed_at
 * @property string $processing_status
 * @property string|null $processing_error
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
#[Fillable([
    'source_id',
    'external_id',
    'raw_payload',
    'fetched_at',
    'processed_at',
    'processing_status',
    'processing_error',
])]

class IngestRecord extends Model
{
    /** @use HasFactory<IngestRecordFactory> */
    use HasFactory;

    protected function casts(): array
    {
        return [
            'raw_payload' => 'array',
            'fetched_at' => 'datetime',
            'processed_at' => 'datetime',
        ];
    }
}
