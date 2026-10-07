<?php

namespace Database\Factories;

use App\Models\Format;
use App\Models\ParsedRecord;
use App\Models\VersionRange;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<VersionRange>
 */
class VersionRangeFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'parsed_record_id' => ParsedRecord::factory(),
            'format_id' => Format::factory(),
            'type' => 'a',
            'ecosystem' => null,
            'package_manager' => null,
            'vendor' => fake()->word(),
            'product' => fake()->word(),
            'version_incl_start' => '1.0.0',
            'version_excl_start' => null,
            'version_incl_end' => null,
            'version_excl_end' => '2.0.0',
            'version_scope' => 'range',
            'confidence' => 'high',
            'plugs_into' => null,
            'raw' => null,
        ];
    }
}
