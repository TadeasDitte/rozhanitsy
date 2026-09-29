<?php

namespace App\Models;

use Database\Factories\AliasFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $parsed_record_id
 * @property string $alias
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
final class Alias extends Model
{
    /** @use HasFactory<AliasFactory> */
    use HasFactory;

    protected $guarded = [];

    /**
     * @return BelongsTo<ParsedRecord, $this>
     */
    public function parsedRecord(): BelongsTo
    {
        return $this->belongsTo(ParsedRecord::class);
    }
}
