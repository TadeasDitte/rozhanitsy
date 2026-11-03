<?php

namespace App\Models;

use Database\Factories\SourceFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $name
 * @property string $slug
 * @property string $url
 * @property string|null $ingest_base_url
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 * @property-read int $parsed_records_count loaded by withCount() in the source-status MCP tool, as are the counts below
 * @property-read int $unresolved_records_count
 * @property-read int $pending_records_count
 * @property-read int $failed_records_count
 * @property-read string|null $parsed_records_max_last_modified_at loaded by withMax()
 **/
#[Fillable(['name', 'slug', 'url', 'ingest_base_url'])]

class Source extends Model
{
    /** @use HasFactory<SourceFactory> */
    use HasFactory;

    /**
     * @return HasOne<SyncState, $this>
     */
    public function syncState(): HasOne
    {
        return $this->hasOne(SyncState::class);
    }

    /**
     * @return HasMany<IngestRecord, $this>
     */
    public function ingestRecords(): HasMany
    {
        return $this->hasMany(IngestRecord::class);
    }

    /**
     * @return HasMany<ParsedRecord, $this>
     */
    public function parsedRecords(): HasMany
    {
        return $this->hasMany(ParsedRecord::class);
    }
}
