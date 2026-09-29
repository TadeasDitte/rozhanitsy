<?php

use App\Models\Format;
use App\Models\IngestRecord;
use App\Models\ParsedRecord;
use App\Models\Source;

/**
 * @return array<string, mixed>
 */
function fastOsvPayload(string $id): array
{
    return [
        'id' => $id,
        'aliases' => ['CVE-2026-1'],
        'affected' => [
            [
                'package' => ['ecosystem' => 'npm', 'name' => 'left-pad', 'purl' => 'pkg:npm/left-pad'],
                'ranges' => [
                    ['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.3.0']]],
                ],
            ],
        ],
    ];
}

test('runs L1 and L2 for each pending record in one pass', function () {
    Format::factory()->purl()->create();
    $source = Source::factory()->create(['slug' => 'osv']);
    $ingest = IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'pending',
        'raw_payload' => fastOsvPayload('GHSA-fast'),
    ]);

    $this->artisan('parse:fast', ['source' => 'osv'])->assertSuccessful();

    expect($ingest->refresh()->processing_status)->toBe('processed');

    $parsed = ParsedRecord::where('ingest_record_id', $ingest->id)->sole();
    expect($parsed->resolved_at)->not->toBeNull();
    expect($parsed->aliases()->pluck('alias')->all())->toBe(['CVE-2026-1']);
    expect($parsed->versionRanges()->sole()->product)->toBe('left-pad');
});

test('also resolves parsed records left unresolved by an earlier L1-only run', function () {
    Format::factory()->purl()->create();
    $source = Source::factory()->create(['slug' => 'osv']);
    $leftover = ParsedRecord::factory()->ofSource($source)->create([
        'raw_ranges' => fastOsvPayload('GHSA-leftover')['affected'],
    ]);

    $this->artisan('parse:fast', ['source' => 'osv'])
        ->expectsOutputToContain('Resolving 1 leftover parsed records for osv')
        ->assertSuccessful();

    expect($leftover->refresh()->resolved_at)->not->toBeNull();
    expect($leftover->versionRanges)->toHaveCount(1);
});

test('falls back to L1 only when the format row is missing', function () {
    $source = Source::factory()->create(['slug' => 'osv']);
    $ingest = IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'pending',
        'raw_payload' => fastOsvPayload('GHSA-no-format'),
    ]);

    $this->artisan('parse:fast', ['source' => 'osv'])
        ->expectsOutputToContain('No format row for slug [osv]')
        ->assertSuccessful();

    $parsed = ParsedRecord::where('ingest_record_id', $ingest->id)->sole();
    expect($parsed->resolved_at)->toBeNull();
    expect($parsed->versionRanges)->toHaveCount(0);
});

test('--rerun reparses processed records through both layers', function () {
    Format::factory()->purl()->create();
    $source = Source::factory()->create(['slug' => 'osv']);
    $ingest = IngestRecord::factory()->create([
        'source_id' => $source->id,
        'processing_status' => 'processed',
        'raw_payload' => fastOsvPayload('GHSA-rerun'),
    ]);
    $parsed = ParsedRecord::factory()->resolved()->create([
        'ingest_record_id' => $ingest->id,
        'source_id' => $source->id,
        'external_id' => 'stale-value',
    ]);

    $this->artisan('parse:fast', ['source' => 'osv', '--rerun' => true])->assertSuccessful();

    expect($parsed->refresh()->external_id)->toBe('GHSA-rerun');
    expect($parsed->resolved_at)->not->toBeNull();
    expect($parsed->versionRanges)->toHaveCount(1);
});
