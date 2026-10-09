<?php

use App\Ingestion\Parsers\OSVRangeParser;

/**
 * @param  list<array<string, mixed>>  $ranges
 * @return list<array<string, mixed>>
 */
function osvAffected(array $ranges, array $package = ['ecosystem' => 'npm', 'name' => 'left-pad']): array
{
    return [['package' => $package, 'ranges' => $ranges]];
}

test('turns an introduced-zero / fixed pair into a range open at the start', function () {
    $ranges = (new OSVRangeParser)->parse(osvAffected([
        ['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.2.3']]],
    ]));

    expect($ranges)->toHaveCount(1);
    expect($ranges[0]->type)->toBe('a');
    expect($ranges[0]->ecosystem)->toBe('npm');
    expect($ranges[0]->product)->toBe('left-pad');
    expect($ranges[0]->vendor)->toBeNull();
    expect($ranges[0]->versionInclStart)->toBeNull();
    expect($ranges[0]->versionExclEnd)->toBe('1.2.3');
    expect($ranges[0]->versionInclEnd)->toBeNull();
});

test('uses last_affected as an inclusive upper bound', function () {
    $ranges = (new OSVRangeParser)->parse(osvAffected([
        ['type' => 'SEMVER', 'events' => [['introduced' => '2.0.0'], ['last_affected' => '2.4.1']]],
    ]));

    expect($ranges[0]->versionInclStart)->toBe('2.0.0');
    expect($ranges[0]->versionInclEnd)->toBe('2.4.1');
    expect($ranges[0]->versionExclEnd)->toBeNull();
});

test('emits one range per introduced pair inside a single events list', function () {
    $ranges = (new OSVRangeParser)->parse(osvAffected([
        ['type' => 'SEMVER', 'events' => [
            ['introduced' => '0'], ['fixed' => '1.0.0'],
            ['introduced' => '2.0.0'], ['fixed' => '2.1.0'],
        ]],
    ]));

    expect($ranges)->toHaveCount(2);
    expect($ranges[0]->versionExclEnd)->toBe('1.0.0');
    expect($ranges[1]->versionInclStart)->toBe('2.0.0');
    expect($ranges[1]->versionExclEnd)->toBe('2.1.0');
});

test('emits an open-ended range for an introduced event with no terminator', function () {
    $ranges = (new OSVRangeParser)->parse(osvAffected([
        ['type' => 'SEMVER', 'events' => [['introduced' => '1.5.0']]],
    ]));

    expect($ranges)->toHaveCount(1);
    expect($ranges[0]->versionInclStart)->toBe('1.5.0');
    expect($ranges[0]->versionExclEnd)->toBeNull();
    expect($ranges[0]->versionInclEnd)->toBeNull();
});

test('treats an ECOSYSTEM range the same as SEMVER', function () {
    $ranges = (new OSVRangeParser)->parse(osvAffected([
        ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '3.0.0']]],
    ]));

    expect($ranges)->toHaveCount(1);
    expect($ranges[0]->versionExclEnd)->toBe('3.0.0');
});

test('skips GIT ranges', function () {
    $ranges = (new OSVRangeParser)->parse(osvAffected([
        ['type' => 'GIT', 'repo' => 'https://example.test/repo', 'events' => [
            ['introduced' => '0'], ['fixed' => 'a1b2c3d4'],
        ]],
    ]));

    expect($ranges)->toBe([]);
});

test('reads the vendor from a purl namespace', function () {
    $ranges = (new OSVRangeParser)->parse([[
        'package' => [
            'ecosystem' => 'Packagist',
            'name' => 'monolog/monolog',
            'purl' => 'pkg:composer/monolog/monolog',
        ],
        'ranges' => [
            ['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.0.0']]],
        ],
    ]]);

    expect($ranges[0]->vendor)->toBe('monolog');
    expect($ranges[0]->product)->toBe('monolog/monolog');
    expect($ranges[0]->raw)->toContain('pkg:composer/monolog/monolog');
});

test('reads the package manager from the purl type', function () {
    $ranges = (new OSVRangeParser)->parse([[
        'package' => [
            'ecosystem' => 'Debian',
            'name' => 'nginx',
            'purl' => 'pkg:deb/debian/nginx',
        ],
        'ranges' => [
            ['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '1.18.0']]],
        ],
    ]]);

    expect($ranges[0]->packageManager)->toBe('deb');
    expect($ranges[0]->ecosystem)->toBe('Debian');
});

test('reads the package manager from a purl with no namespace', function () {
    $ranges = (new OSVRangeParser)->parse([[
        'package' => [
            'ecosystem' => 'npm',
            'name' => 'left-pad',
            'purl' => 'pkg:npm/left-pad',
        ],
        'ranges' => [
            ['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.0.0']]],
        ],
    ]]);

    expect($ranges[0]->packageManager)->toBe('npm');
    expect($ranges[0]->vendor)->toBeNull();
});

test('leaves the package manager null when there is no purl', function () {
    $ranges = (new OSVRangeParser)->parse(osvAffected([
        ['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.2.3']]],
    ]));

    expect($ranges[0]->packageManager)->toBeNull();
});

test('skips an affected entry that has only a versions list and no ranges', function () {
    $ranges = (new OSVRangeParser)->parse([[
        'package' => ['ecosystem' => 'PyPI', 'name' => 'django'],
        'versions' => ['1.0', '1.1', '1.2'],
    ]]);

    expect($ranges)->toBe([]);
});

test('returns an empty list when there are no affected entries', function () {
    expect((new OSVRangeParser)->parse([]))->toBe([]);
});

test('lowercases Packagist package names and vendors only', function (array $package, string $vendor, string $product) {
    $ranges = (new OSVRangeParser)->parse(osvAffected(
        [['type' => 'ECOSYSTEM', 'events' => [['introduced' => '0'], ['fixed' => '2.1.70']]]],
        $package,
    ));

    expect([$ranges[0]->vendor, $ranges[0]->product])->toBe([$vendor, $product]);
})->with([
    'Packagist' => [['ecosystem' => 'Packagist', 'name' => 'Studio-42/elFinder', 'purl' => 'pkg:composer/Studio-42/elFinder'], 'studio-42', 'studio-42/elfinder'],
    'npm' => [['ecosystem' => 'npm', 'name' => '@Scope/Pkg', 'purl' => 'pkg:npm/%40Scope/Pkg'], '@Scope', '@Scope/Pkg'],
]);
