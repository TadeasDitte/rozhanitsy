<?php

use App\Mcp\Servers\RozhanitsyServer;
use App\Mcp\Tools\SourceStatus;
use App\Models\IngestRecord;
use App\Models\ParsedRecord;
use App\Models\Source;
use App\Models\SyncState;

test('reports when each source synced, its newest record and its parse backlog', function () {
    $nvd = Source::factory()->create(['slug' => 'nvd', 'name' => 'NVD', 'url' => 'https://nvd.nist.gov/']);
    SyncState::create(['source_id' => $nvd->id, 'last_synced_at' => '2026-11-03 06:00:00']);
    ParsedRecord::factory()->for($nvd)->for(IngestRecord::factory()->state(['source_id' => $nvd->id]))->create(['last_modified_at' => '2026-11-02 10:00:00', 'resolved_at' => now()]);
    ParsedRecord::factory()->for($nvd)->for(IngestRecord::factory()->state(['source_id' => $nvd->id]))->create(['last_modified_at' => '2026-11-03 05:00:00', 'resolved_at' => null]);
    IngestRecord::factory()->state(['source_id' => $nvd->id])->count(3)->create(['processing_status' => 'pending']);
    IngestRecord::factory()->state(['source_id' => $nvd->id])->create(['processing_status' => 'failed']);

    Source::factory()->create(['slug' => 'osv', 'name' => 'Open Source Vulnerabilities', 'url' => 'https://osv.dev/']);

    RozhanitsyServer::tool(SourceStatus::class)
        ->assertOk()
        ->assertStructuredContent(['sources' => [
            [
                'slug' => 'nvd',
                'name' => 'NVD',
                'url' => 'https://nvd.nist.gov/',
                'last_synced_at' => '2026-11-03T06:00:00+00:00',
                'latest_record_modified_at' => '2026-11-03T05:00:00+00:00',
                'parsed_records' => 2,
                'unresolved_records' => 1,
                'pending_records' => 3,
                'failed_records' => 1,
            ],
            [
                'slug' => 'osv',
                'name' => 'Open Source Vulnerabilities',
                'url' => 'https://osv.dev/',
                'last_synced_at' => null,
                'latest_record_modified_at' => null,
                'parsed_records' => 0,
                'unresolved_records' => 0,
                'pending_records' => 0,
                'failed_records' => 0,
            ],
        ]]);
});
