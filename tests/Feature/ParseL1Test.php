<?php

use App\Models\Alias;
use App\Models\IngestRecord;
use App\Models\ParsedRecord;
use App\Models\Source;

test('--rerun requeues already-processed records and parses them again', function () {
    $source = Source::factory()->create(['slug' => 'osv']);
    $ingest = IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'processed',
        'processed_at' => now()->subDay(),
        'raw_payload' => ['id' => 'GHSA-aaaa-bbbb-cccc', 'summary' => 'x'],
    ]);
    $parsed = ParsedRecord::factory()->create([
        'ingest_record_id' => $ingest->id,
        'source_id' => $source->id,
        'external_id' => 'stale-value',
        'resolved_at' => now(),
    ]);

    $this->artisan('parse:l1', ['source' => 'osv', '--rerun' => true])
        ->expectsOutputToContain('Requeued 1 already-processed records for osv')
        ->assertSuccessful();

    expect($ingest->refresh()->processing_status)->toBe('processed');
    expect($parsed->refresh()->external_id)->toBe('GHSA-aaaa-bbbb-cccc');
    expect($parsed->resolved_at)->toBeNull();
    expect(ParsedRecord::where('ingest_record_id', $ingest->id)->count())->toBe(1);
});

test('--rerun also requeues skipped records', function () {
    $source = Source::factory()->create(['slug' => 'osv']);
    $ingest = IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'skipped',
        'raw_payload' => ['id' => 'GHSA-skip-me', 'summary' => 'x'],
    ]);

    $this->artisan('parse:l1', ['source' => 'osv', '--rerun' => true])->assertSuccessful();

    expect($ingest->refresh()->processing_status)->toBe('processed');
    expect(ParsedRecord::where('ingest_record_id', $ingest->id)->count())->toBe(1);
});

test('--rerun leaves failed records for --retry-failed', function () {
    $source = Source::factory()->create(['slug' => 'osv']);
    $ingest = IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'failed',
        'processing_error' => 'boom',
        'raw_payload' => ['id' => 'GHSA-broke', 'summary' => 'x'],
    ]);

    $this->artisan('parse:l1', ['source' => 'osv', '--rerun' => true])
        ->expectsOutputToContain('Nothing pending for osv')
        ->assertSuccessful();

    expect($ingest->refresh()->processing_status)->toBe('failed');
    expect(ParsedRecord::count())->toBe(0);
});

test('without --rerun an already-processed record is left untouched', function () {
    $source = Source::factory()->create(['slug' => 'osv']);
    IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'processed',
        'raw_payload' => ['id' => 'GHSA-done', 'summary' => 'x'],
    ]);

    $this->artisan('parse:l1', ['source' => 'osv'])
        ->expectsOutputToContain('Nothing pending for osv')
        ->assertSuccessful();

    expect(ParsedRecord::count())->toBe(0);
});

test('--rerun only requeues records for the named source', function () {
    $osv = Source::factory()->create(['slug' => 'osv']);
    $nvd = Source::factory()->create(['slug' => 'nvd']);
    $osvIngest = IngestRecord::factory()->create([
        'source_id' => $osv->id,
        'processing_status' => 'processed',
        'raw_payload' => ['id' => 'GHSA-osv', 'summary' => 'x'],
    ]);
    $nvdIngest = IngestRecord::factory()->create([
        'source_id' => $nvd->id,
        'processing_status' => 'processed',
        'raw_payload' => ['id' => 'CVE-2024-9999'],
    ]);

    $this->artisan('parse:l1', ['source' => 'osv', '--rerun' => true])->assertSuccessful();

    expect($osvIngest->refresh()->processing_status)->toBe('processed');
    expect($nvdIngest->refresh()->processing_status)->toBe('processed');
    expect(ParsedRecord::where('ingest_record_id', $osvIngest->id)->count())->toBe(1);
    expect(ParsedRecord::where('ingest_record_id', $nvdIngest->id)->count())->toBe(0);
});

test('writes aliases to their own table, deduplicated', function () {
    $source = Source::factory()->create(['slug' => 'osv']);
    $ingest = IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'pending',
        'raw_payload' => ['id' => 'GHSA-with-alias', 'aliases' => ['CVE-2026-1', 'CVE-2026-2', 'CVE-2026-1']],
    ]);

    $this->artisan('parse:l1', ['source' => 'osv'])->assertSuccessful();

    $parsed = ParsedRecord::where('ingest_record_id', $ingest->id)->sole();
    expect($parsed->aliases()->pluck('alias')->sort()->values()->all())->toBe(['CVE-2026-1', 'CVE-2026-2']);
});

test('--rerun replaces stale aliases', function () {
    $source = Source::factory()->create(['slug' => 'osv']);
    $ingest = IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'processed',
        'raw_payload' => ['id' => 'GHSA-with-alias', 'aliases' => ['CVE-2026-1']],
    ]);
    $parsed = ParsedRecord::factory()->create(['ingest_record_id' => $ingest->id, 'source_id' => $source->id]);
    Alias::factory()->for($parsed)->create(['alias' => 'CVE-1999-stale']);

    $this->artisan('parse:l1', ['source' => 'osv', '--rerun' => true])->assertSuccessful();

    expect($parsed->aliases()->pluck('alias')->all())->toBe(['CVE-2026-1']);
});
