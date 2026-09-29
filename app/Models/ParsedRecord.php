<?php

namespace App\Models;

use Database\Factories\ParsedRecordFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

final class ParsedRecord extends Model
{
    /** @use HasFactory<ParsedRecordFactory> */
    use HasFactory;

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'weaknesses' => 'array',
            'references' => 'array',
            'raw_ranges' => 'array',
            'published_at' => 'datetime',
            'last_modified_at' => 'datetime',
            'resolved_at' => 'datetime',
            'known_exploited' => 'boolean',
            'cvss_score' => 'decimal:1',
        ];
    }

    public function ingestRecord(): BelongsTo
    {
        return $this->belongsTo(IngestRecord::class);
    }

    public function source(): BelongsTo
    {
        return $this->belongsTo(Source::class);
    }

    /**
     * @return HasMany<Alias, $this>
     */
    public function aliases(): HasMany
    {
        return $this->hasMany(Alias::class);
    }

    /**
     * @return HasMany<VersionRange, $this>
     */
    public function versionRanges(): HasMany
    {
        return $this->hasMany(VersionRange::class);
    }
}
