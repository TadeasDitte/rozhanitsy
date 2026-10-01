<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $source_id
 * @property array<string, mixed>|null $cursor
 * @property Carbon|null $last_synced_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
#[Fillable(['source_id', 'cursor', 'last_synced_at'])]
class SyncState extends Model
{
    protected function casts(): array
    {
        return [
            'cursor' => 'array',
            'last_synced_at' => 'datetime',
        ];
    }
}
