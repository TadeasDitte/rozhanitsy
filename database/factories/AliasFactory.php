<?php

namespace Database\Factories;

use App\Models\Alias;
use App\Models\ParsedRecord;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Alias>
 */
class AliasFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'parsed_record_id' => ParsedRecord::factory(),
            'alias' => 'CVE-'.fake()->year().'-'.fake()->numberBetween(1000, 99999),
        ];
    }
}
