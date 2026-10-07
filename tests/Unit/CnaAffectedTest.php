<?php

use App\Ingestion\Support\CnaAffected;

/**
 * @param  list<array<string, mixed>>  $versions
 * @param  array<string, mixed>  $entry
 * @return array<string, mixed>
 */
function cnaEntry(array $versions, array $entry = []): array
{
    return [...['packageName' => 'perl', 'defaultStatus' => 'unaffected'], ...$entry, 'versions' => $versions];
}

/**
 * @param  array<string, mixed>  $entry
 * @return list<array<string, ?string>>
 */
function cnaBounds(array $entry): array
{
    return array_map(
        fn (array $bounds): array => array_diff_key($bounds, ['raw' => true]),
        CnaAffected::parse($entry)->ranges,
    );
}

test('reads a version with lessThan as a range that excludes its end', function () {
    $bounds = cnaBounds(cnaEntry([
        ['version' => '5.41.0', 'lessThan' => '5.42.3-RC1', 'versionType' => 'custom', 'status' => 'affected'],
    ]));

    expect($bounds)->toBe([['startIncl' => '5.41.0', 'startExcl' => null, 'endIncl' => null, 'endExcl' => '5.42.3-RC1']]);
});

test('reads lessThanOrEqual as an inclusive end and version 0 as no start', function () {
    $bounds = cnaBounds(cnaEntry([
        ['version' => '0', 'lessThanOrEqual' => '1.8.8', 'status' => 'affected'],
    ]));

    expect($bounds)->toBe([['startIncl' => null, 'startExcl' => null, 'endIncl' => '1.8.8', 'endExcl' => null]]);
});

test('reads a wildcard upper bound as open ended', function () {
    $bounds = cnaBounds(cnaEntry([
        ['version' => '2.0', 'lessThanOrEqual' => '*', 'status' => 'affected'],
    ]));

    expect($bounds)->toBe([['startIncl' => '2.0', 'startExcl' => null, 'endIncl' => null, 'endExcl' => null]]);
});

test('reads a bare version as an exact match', function () {
    $bounds = cnaBounds(cnaEntry([['version' => '1.2.3', 'status' => 'affected']]));

    expect($bounds)->toBe([['startIncl' => '1.2.3', 'startExcl' => null, 'endIncl' => '1.2.3', 'endExcl' => null]]);
});

test('reads comparator expressions', function (string $expression, array $expected) {
    $bounds = cnaBounds(cnaEntry([['version' => $expression, 'status' => 'affected']]));

    expect($bounds[0])->toBe($expected);
})->with([
    'upper bound' => ['< 3.0.1', ['startIncl' => null, 'startExcl' => null, 'endIncl' => null, 'endExcl' => '3.0.1']],
    'both bounds' => ['>= 3.1.0, < 3.1.2', ['startIncl' => '3.1.0', 'startExcl' => null, 'endIncl' => null, 'endExcl' => '3.1.2']],
    'exclusive start inclusive end' => ['> 1.0, <= 1.5', ['startIncl' => null, 'startExcl' => '1.0', 'endIncl' => '1.5', 'endExcl' => null]],
    'equals' => ['= 2.4', ['startIncl' => '2.4', 'startExcl' => null, 'endIncl' => '2.4', 'endExcl' => null]],
]);

test('keeps every affected range and ignores unaffected ones', function () {
    $entry = cnaEntry([
        ['version' => '0', 'lessThan' => '5.40.5-RC1', 'status' => 'affected'],
        ['version' => '5.40.5-RC1', 'status' => 'unaffected'],
        ['version' => '5.43.0', 'lessThan' => '5.43.11', 'status' => 'affected'],
    ]);

    expect(CnaAffected::parse($entry)->ranges)->toHaveCount(2);
});

test('gives up on entries that are not plain ranges', function (array $entry) {
    expect(CnaAffected::parse($entry))->toBeNull();
})->with([
    'placeholder version' => [cnaEntry([['version' => 'n/a', 'status' => 'affected']])],
    'unspecified version' => [cnaEntry([['version' => 'unspecified', 'status' => 'affected']])],
    'version 0 alone' => [cnaEntry([['version' => '0', 'status' => 'affected']])],
    'unreadable free text' => [cnaEntry([['version' => 'before 1.2 on Windows', 'status' => 'affected']])],
    'repeated comparator' => [cnaEntry([['version' => '< 1.0, < 2.0', 'status' => 'affected']])],
    'unreadable bound' => [cnaEntry([['version' => '1.0', 'lessThan' => 'soon', 'status' => 'affected']])],
    'one unreadable range among good ones' => [cnaEntry([
        ['version' => '0', 'lessThan' => '1.0', 'status' => 'affected'],
        ['version' => 'n/a', 'status' => 'affected'],
    ])],
    'affected by default' => [cnaEntry([['version' => '2.0', 'status' => 'unaffected']], ['defaultStatus' => 'affected'])],
    'nothing affected' => [cnaEntry([['version' => '2.0', 'status' => 'unaffected']])],
    'no product name' => [cnaEntry([['version' => '0', 'lessThan' => '1.0', 'status' => 'affected']], ['packageName' => 'n/a'])],
]);

test('matches a CPE vendor and product by name ignoring case and punctuation', function (array $names, ?string $vendor, string $product, bool $expected) {
    $cna = CnaAffected::parse(cnaEntry(
        [['version' => '0', 'lessThan' => '1.0', 'status' => 'affected']],
        ['packageName' => null, ...$names],
    ));

    expect($cna->isAbout($vendor, $product))->toBe($expected);
})->with([
    'package name' => [['packageName' => 'perl'], 'perl', 'perl', true],
    'product' => [['vendor' => 'ruby', 'product' => 'zlib'], 'ruby-lang', 'zlib', true],
    'vendor and product joined' => [['vendor' => 'Apache Software Foundation', 'product' => 'Apache ORC'], 'apache', 'orc', true],
    'module' => [['modules' => ['Net::HTTP']], null, 'net_http', true],
    'other product' => [['packageName' => 'perl'], 'python', 'python', false],
]);

test('reads a range that starts and ends at the same version as everything below it', function (string $start) {
    $bounds = cnaBounds(cnaEntry([['version' => $start, 'lessThan' => '3.1.0', 'status' => 'affected']]));

    expect($bounds)->toBe([['startIncl' => null, 'startExcl' => null, 'endIncl' => null, 'endExcl' => '3.1.0']]);
})->with([
    'WPScan' => ['3.1.0'],
    'Wordfence' => ['*'],
]);

test('reads an entry affected by default as one open range', function (array $versions, ?string $fixedIn) {
    $bounds = cnaBounds(cnaEntry($versions, ['defaultStatus' => 'affected']));

    expect($bounds)->toBe([['startIncl' => null, 'startExcl' => null, 'endIncl' => null, 'endExcl' => $fixedIn]]);
})->with([
    'never fixed' => [[], null],
    'ignores affected items' => [[['version' => 'n/a', 'status' => 'affected']], null],
    'fixed from a version on' => [[['version' => '6.1', 'lessThan' => '*', 'status' => 'unaffected']], '6.1'],
]);

test('gives up on an entry affected by default with unaffected branches', function () {
    expect(CnaAffected::parse(cnaEntry([
        ['version' => '6.1.50', 'lessThanOrEqual' => '6.1.*', 'status' => 'unaffected'],
        ['version' => '6.6', 'lessThanOrEqual' => '*', 'status' => 'unaffected'],
    ], ['defaultStatus' => 'affected'])))->toBeNull();
});

test('names the product after its CPE, package name or product name', function (array $names, ?string $vendor, string $product) {
    $cna = CnaAffected::parse(cnaEntry(
        [['version' => '0', 'lessThan' => '1.0', 'status' => 'affected']],
        ['packageName' => null, ...$names],
    ));

    expect([$cna->vendor, $cna->product])->toBe([$vendor, $product]);
})->with([
    'cpe' => [['product' => 'Astra', 'cpes' => ['cpe:2.3:a:brainstormforce:astra:*:*:*:*:*:wordpress:*:*']], 'brainstormforce', 'astra'],
    'package name' => [['vendor' => 'n/a', 'packageName' => 'guzzlehttp/psr7'], null, 'guzzlehttp/psr7'],
    'product name' => [['vendor' => 'Cookie Information', 'product' => 'WP GDPR Compliance'], 'cookieinformation', 'wp-gdpr-compliance'],
]);

test('tells an everything-affected default apart from listed versions', function (string $defaultStatus, bool $expected) {
    $cna = CnaAffected::parse(cnaEntry([['version' => '0', 'lessThan' => '1.0', 'status' => 'affected']], ['defaultStatus' => $defaultStatus]));

    expect($cna->isAffectedByDefault)->toBe($expected);
})->with([
    'affected' => ['affected', true],
    'unaffected' => ['unaffected', false],
]);
