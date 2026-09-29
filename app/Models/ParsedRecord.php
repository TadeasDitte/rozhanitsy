<?php

namespace App\Models;

use Database\Factories\ParsedRecordFactory;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $ingest_record_id
 * @property int $source_id
 * @property string $external_id
 * @property string|null $cvss_score
 * @property string|null $cvss_vector
 * @property string|null $cvss_version
 * @property string|null $cvss_severity
 * @property string|null $description
 * @property Carbon|null $published_at
 * @property Carbon|null $last_modified_at
 * @property list<string>|null $weaknesses
 * @property array<int, mixed>|null $references
 * @property string|null $status
 * @property bool $known_exploited
 * @property array<int, mixed> $raw_ranges
 * @property Carbon|null $resolved_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
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

    /**
     * Scope to records that have not been withdrawn (OSV) or rejected (NVD).
     *
     * @param  Builder<ParsedRecord>  $query
     */
    #[Scope]
    protected function active(Builder $query): void
    {
        $query->where(function (Builder $query): void {
            $query->whereNull('status')->orWhereNotIn('status', ['withdrawn', 'Rejected']);
        });
    }

    /**
     * @return BelongsTo<IngestRecord, $this>
     */
    public function ingestRecord(): BelongsTo
    {
        return $this->belongsTo(IngestRecord::class);
    }

    /**
     * @return BelongsTo<Source, $this>
     */
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
