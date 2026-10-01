<?php

namespace Database\Seeders;

use App\Models\Format;
use Illuminate\Database\Seeder;

class FormatSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        Format::create([
            'name' => 'cpe',
            'version' => '2.3',
        ]);
        Format::create([
            'name' => 'purl',
        ]);
    }
}
