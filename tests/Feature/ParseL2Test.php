<?php

use App\Models\Format;
use App\Models\ParsedRecord;
use App\Models\Source;
use App\Models\VersionRange;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;

function seedL2Formats(): void
{
    Format::factory()->cpe()->create();
    Format::factory()->purl()->create();
}

/**
 * @return list<array<string, mixed>>
 */
function l2NvdConfigurations(): array
{
    return [
        [
            'nodes' => [
                [
                    'negate' => false,
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'criteria' => 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',
                            'vulnerable' => true,
                            'versionStartIncluding' => '6.9',
                            'versionEndExcluding' => '6.9.5',
                        ],
                        [
                            'criteria' => 'cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*',
                            'vulnerable' => true,
                            'versionStartIncluding' => '7.0',
                            'versionEndExcluding' => '7.0.2',
                        ],
                    ],
                ],
            ],
        ],
    ];
}

/**
 * @return list<array<string, mixed>>
 */
function l2OsvAffected(): array
{
    return [
        [
            'package' => ['ecosystem' => 'npm', 'name' => 'left-pad', 'purl' => 'pkg:npm/left-pad'],
            'ranges' => [
                ['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.3.0']]],
            ],
        ],
        [
            'package' => ['ecosystem' => 'PyPI', 'name' => 'django'],
            'ranges' => [
                ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '2.0'], ['last_affected' => '2.2']]],
            ],
        ],
    ];
}

test('expands NVD CPE ranges into version_ranges and stamps resolved_at', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => l2NvdConfigurations()]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    $record->refresh();
    expect($record->resolved_at)->not->toBeNull();
    expect($record->versionRanges)->toHaveCount(2);

    $first = $record->versionRanges()->orderBy('version_incl_start')->first();
    expect($first->format_id)->toBe(Format::where('name', 'cpe')->value('id'));
    expect($first->type)->toBe('a');
    expect($first->vendor)->toBe('wordpress');
    expect($first->product)->toBe('wordpress');
    expect($first->version_incl_start)->toBe('6.9');
    expect($first->version_excl_end)->toBe('6.9.5');
    expect($first->raw)->toBe('cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*');
});

test('expands OSV PURL ranges into version_ranges', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'osv']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => l2OsvAffected()]);

    $this->artisan('parse:l2', ['source' => 'osv'])->assertSuccessful();

    expect($record->refresh()->versionRanges)->toHaveCount(2);

    $npm = $record->versionRanges()->where('ecosystem', 'npm')->first();
    expect($npm->format_id)->toBe(Format::where('name', 'purl')->value('id'));
    expect($npm->type)->toBe('a');
    expect($npm->package_manager)->toBe('npm');
    expect($npm->product)->toBe('left-pad');
    expect($npm->version_incl_start)->toBeNull();
    expect($npm->version_excl_end)->toBe('1.3.0');

    $py = $record->versionRanges()->where('ecosystem', 'PyPI')->first();
    expect($py->version_incl_start)->toBe('2.0');
    expect($py->version_incl_end)->toBe('2.2');
});

test('leaves an already-resolved record untouched', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $record = ParsedRecord::factory()->ofSource($source)->resolved()
        ->create(['raw_ranges' => l2NvdConfigurations()]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    expect($record->refresh()->versionRanges)->toHaveCount(0);
});

test('running twice does not duplicate version ranges', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => l2NvdConfigurations()]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();
    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    expect(VersionRange::where('parsed_record_id', $record->id)->count())->toBe(2);
});

test('--rerun replaces existing rows and re-stamps resolved_at', function () {
    seedL2Formats();
    $this->freezeTime();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => l2NvdConfigurations()]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();
    $firstResolvedAt = $record->refresh()->resolved_at;

    $stale = VersionRange::factory()->create([
        'parsed_record_id' => $record->id,
        'format_id' => Format::where('name', 'cpe')->value('id'),
        'product' => 'stale-row',
    ]);

    $this->travel(1)->hour();
    $this->artisan('parse:l2', ['source' => 'nvd', '--rerun' => true])->assertSuccessful();

    expect(VersionRange::find($stale->id))->toBeNull();
    expect(VersionRange::where('parsed_record_id', $record->id)->count())->toBe(2);
    expect($record->refresh()->resolved_at->gt($firstResolvedAt))->toBeTrue();
});

test('a record whose ranges cannot be parsed is reported and left unresolved', function () {
    Exceptions::fake();
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $good = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => l2NvdConfigurations()]);
    $bad = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => [
        ['nodes' => [['cpeMatch' => [['criteria' => 'garbage', 'vulnerable' => true]]]]],
    ]]);

    $this->artisan('parse:l2', ['source' => 'nvd'])
        ->expectsOutputToContain('1 records could not be resolved for nvd')
        ->assertSuccessful();

    expect($good->refresh()->resolved_at)->not->toBeNull();
    expect($good->versionRanges)->toHaveCount(2);
    expect($bad->refresh()->resolved_at)->toBeNull();
    Exceptions::assertReported(InvalidArgumentException::class);
});

test('only resolves records for the named source', function () {
    seedL2Formats();
    $nvd = Source::factory()->create(['slug' => 'nvd']);
    $osv = Source::factory()->create(['slug' => 'osv']);
    $nvdRecord = ParsedRecord::factory()->ofSource($nvd)->create(['raw_ranges' => l2NvdConfigurations()]);
    $osvRecord = ParsedRecord::factory()->ofSource($osv)->create(['raw_ranges' => l2OsvAffected()]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    expect($nvdRecord->refresh()->resolved_at)->not->toBeNull();
    expect($osvRecord->refresh()->resolved_at)->toBeNull();
});

test('warns and skips a source with no range parser class', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'foobar']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => []]);

    $this->artisan('parse:l2')
        ->expectsOutputToContain('No range parser class found for slug [foobar]')
        ->assertSuccessful();

    expect($record->refresh()->resolved_at)->toBeNull();
    expect(VersionRange::count())->toBe(0);
});

test('warns and skips when the format row is missing', function () {
    Format::factory()->purl()->create(); // cpe intentionally absent
    $source = Source::factory()->create(['slug' => 'nvd']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => l2NvdConfigurations()]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    expect($record->refresh()->resolved_at)->toBeNull();
    expect(VersionRange::count())->toBe(0);
});

test('marks a record with no expandable ranges as resolved with zero rows', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => []]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    expect($record->refresh()->resolved_at)->not->toBeNull();
    expect($record->versionRanges)->toHaveCount(0);
});

test('stores the version scope of each range', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => [[
        'nodes' => [['operator' => 'OR', 'cpeMatch' => [
            ['criteria' => 'cpe:2.3:h:acme:router:-:*:*:*:*:*:*:*', 'vulnerable' => true],
            ['criteria' => 'cpe:2.3:a:acme:app:*:*:*:*:*:*:*:*', 'vulnerable' => true],
        ]]],
    ]]]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    expect($record->versionRanges()->pluck('version_scope', 'product')->all())
        ->toBe(['router' => 'na', 'app' => 'any']);
});

test('--partition only resolves records within its id range', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $records = ParsedRecord::factory()->ofSource($source)->count(4)->create(['raw_ranges' => l2NvdConfigurations()]);

    $this->artisan('parse:l2', ['source' => 'nvd', '--partition' => "{$records[0]->id}-{$records[1]->id}"])->assertSuccessful();

    expect($records->map(fn (ParsedRecord $record) => $record->refresh()->resolved_at !== null)->all())
        ->toBe([true, true, false, false]);
});

test('checks a multi-branch fix against the CNA ranges instead of the lossy CPE range', function (string $version, bool $vulnerable, ?string $fixedIn) {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => [
        ['nodes' => [['cpeMatch' => [[
            'criteria' => 'cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*',
            'vulnerable' => true,
            'versionEndIncluding' => '5.43.10',
        ]]]]],
        ['cna' => [[
            'defaultStatus' => 'unaffected',
            'packageName' => 'perl',
            'versions' => [
                ['version' => '0', 'lessThan' => '5.40.5-RC1', 'versionType' => 'custom', 'status' => 'affected'],
                ['version' => '5.41.0', 'lessThan' => '5.42.3-RC1', 'versionType' => 'custom', 'status' => 'affected'],
                ['version' => '5.43.0', 'lessThan' => '5.43.11', 'versionType' => 'custom', 'status' => 'affected'],
            ],
        ]]],
    ]]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    $response = $this->getJson(route('api.v1.check', ['vendor' => 'perl', 'product' => 'perl', 'version' => $version]))
        ->assertJsonPath('data.vulnerable', $vulnerable);

    if ($fixedIn !== null) {
        $response->assertJsonPath('data.vulnerabilities.0.fixed_in', $fixedIn);
    }
})->with([
    'fixed on the 5.42 branch' => ['5.42.3', false, null],
    'fixed on the 5.40 branch' => ['5.40.5', false, null],
    'fixed on the 5.43 branch' => ['5.43.11', false, null],
    'before the 5.42 fix' => ['5.42.2', true, '5.42.3-RC1'],
    'old release' => ['5.30.0', true, '5.40.5-RC1'],
    'development release' => ['5.43.4', true, '5.43.11'],
]);

test('inserts the ranges of a large record in batches that fit the bound parameter limit', function () {
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $matches = array_map(fn (int $minor): array => [
        'criteria' => "cpe:2.3:o:cisco:ios:12.2({$minor}):*:*:*:*:*:*:*",
        'vulnerable' => true,
    ], range(1, 5000));
    $record = ParsedRecord::factory()->ofSource($source)->create([
        'raw_ranges' => [['nodes' => [['operator' => 'OR', 'negate' => false, 'cpeMatch' => $matches]]]],
    ]);
    $boundParameters = [];
    DB::listen(function (QueryExecuted $query) use (&$boundParameters) {
        if (str_starts_with($query->sql, 'insert into "version_ranges"')) {
            $boundParameters[] = count($query->bindings);
        }
    });

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    expect($record->refresh()->resolved_at)->not->toBeNull();
    expect($record->versionRanges()->count())->toBe(5000);
    expect(max($boundParameters))->toBeLessThanOrEqual(65535);
});

test('stamps every resolved range with the same creation time', function () {
    $this->freezeTime();
    seedL2Formats();
    $source = Source::factory()->create(['slug' => 'nvd']);
    $record = ParsedRecord::factory()->ofSource($source)->create(['raw_ranges' => l2NvdConfigurations()]);

    $this->artisan('parse:l2', ['source' => 'nvd'])->assertSuccessful();

    $ranges = $record->versionRanges;
    expect($ranges)->toHaveCount(2);
    $ranges->each(fn (VersionRange $range) => expect($range->created_at->toDateTimeString())->toBe(now()->toDateTimeString())
        ->and($range->updated_at->toDateTimeString())->toBe(now()->toDateTimeString()));
});
