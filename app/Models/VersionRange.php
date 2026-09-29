<?php

namespace App\Models;

use Database\Factories\VersionRangeFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property int $parsed_record_id
 * @property int $format_id
 * @property string $type
 * @property string|null $ecosystem
 * @property string|null $package_manager
 * @property string|null $vendor
 * @property string|null $product
 * @property string|null $version_incl_start
 * @property string|null $version_excl_start
 * @property string|null $version_incl_end
 * @property string|null $version_excl_end
 * @property 'range'|'any'|'na' $version_scope
 * @property string|null $plugs_into
 * @property string|null $raw
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
final class VersionRange extends Model
{
    /** @use HasFactory<VersionRangeFactory> */
    use HasFactory;

    protected $guarded = [];

    /**
     * @return BelongsTo<ParsedRecord, $this>
     */
    public function parsedRecord(): BelongsTo
    {
        return $this->belongsTo(ParsedRecord::class);
    }

    /**
     * @return BelongsTo<Format, $this>
     */
    public function format(): BelongsTo
    {
        return $this->belongsTo(Format::class);
    }
}
