<?php

namespace Database\Seeders;

use App\Models\Source;
use Illuminate\Database\Seeder;

class SourcesSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        Source::create([
            'name' => 'NVD',
            'slug' => 'nvd',
            'url' => 'https://nvd.nist.gov/',
            'ingest_base_url' => 'https://services.nvd.nist.gov/rest/json/cves/2.0/',
        ]);

        Source::create([
            'name' => 'Open Source Vulnerabilities',
            'slug' => 'osv',
            'url' => 'https://osv.dev/',
            'ingest_base_url' => 'https://osv-vulnerabilities.storage.googleapis.com/',
        ]);
    }
}
