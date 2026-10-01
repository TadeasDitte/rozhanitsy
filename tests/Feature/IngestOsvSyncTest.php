<?php

use App\Models\IngestRecord;
use App\Models\Source;
use App\Models\SyncState;
use Illuminate\Support\Facades\Http;

test('--workers downloads every modified record since the cursor, skipping missing ones', function () {
    $source = Source::factory()->create(['slug' => 'osv', 'ingest_base_url' => 'https://osv.test']);
    SyncState::create(['source_id' => $source->id, 'cursor' => ['last_modified' => '2026-01-01T00:00:00Z']]);

    Http::fake([
        'osv.test/modified_id.csv' => Http::response(implode("\n", [
            '2026-01-04T00:00:00Z,npm/GHSA-a',
            '2026-01-03T00:00:00Z,PyPI/GHSA-b',
            '2026-01-02T00:00:00Z,npm/GHSA-gone',
            '2026-01-01T00:00:00Z,npm/GHSA-old',
        ])),
        'osv.test/npm/GHSA-a.json' => Http::response(['id' => 'GHSA-a']),
        'osv.test/PyPI/GHSA-b.json' => Http::response(['id' => 'GHSA-b']),
        'osv.test/npm/GHSA-gone.json' => Http::response(status: 404),
    ]);

    $this->artisan('ingest:osv-sync', ['--workers' => 2])
        ->expectsOutputToContain('Done, 2 records updated, 1 skipped (not found).')
        ->assertSuccessful();

    expect(IngestRecord::where('source_id', $source->id)->orderBy('external_id')->pluck('external_id')->all())
        ->toBe(['GHSA-a', 'GHSA-b']);
    expect(SyncState::where('source_id', $source->id)->sole()->cursor['last_modified'])->toBe('2026-01-04T00:00:00Z');
    Http::assertNotSent(fn ($request) => str_contains($request->url(), 'GHSA-old'));
});
