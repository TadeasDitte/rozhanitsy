<?php

use App\Models\VersionRange;
use App\Services\VersionComparator;

test('orders versions', function (string $lower, string $higher) {
    $comparator = new VersionComparator;

    expect($comparator->compare($lower, $higher))->toBe(-1)
        ->and($comparator->compare($higher, $lower))->toBe(1);
})->with([
    'numeric not lexical' => ['1.9.0', '1.10.0'],
    'shorter release padded with zeros' => ['1.0', '1.0.1'],
    'pre-release before release' => ['1.0.0-rc.1', '1.0.0'],
    'pre-release qualifier order' => ['1.0.0-alpha', '1.0.0-beta'],
    'beta before rc' => ['2.0b1', '2.0rc1'],
    'dev before alpha' => ['1.0.dev1', '1.0a1'],
    'unknown word is a pre-release' => ['1.0.0-foo', '1.0.0'],
    'numeric pre-release identifiers' => ['1.0.0-rc.2', '1.0.0-rc.10'],
    'more pre-release identifiers win' => ['1.0.0-beta', '1.0.0-beta.2'],
    'post-release after release' => ['1.0', '1.0.post1'],
    'post-release before next release' => ['1.0.post1', '1.0.1'],
    'trailing letter is a post-release' => ['1.1.1', '1.1.1a'],
    'trailing letters ordered' => ['1.1.1a', '1.1.1b'],
    'revision after release' => ['2.30', '2.30-1'],
    'epoch wins over release' => ['9.9', '1:1.0'],
    'numbers beyond integer range' => ['1.99999999999999999999', '1.100000000000000000000'],
]);

test('treats equivalent spellings as equal', function (string $a, string $b) {
    expect((new VersionComparator)->compare($a, $b))->toBe(0);
})->with([
    'zero padding' => ['1.0', '1.0.0'],
    'leading v' => ['v1.2.3', '1.2.3'],
    'build metadata' => ['1.2.3+build.5', '1.2.3'],
    'case' => ['1.0.0-RC1', '1.0.0-rc1'],
    'leading zeros' => ['1.02', '1.2'],
    'release qualifier' => ['1.0.Final', '1.0'],
]);

test('checks a version against range bounds', function (array $bounds, string $version, bool $expected) {
    $range = new VersionRange($bounds);

    expect((new VersionComparator)->isInRange($version, $range))->toBe($expected);
})->with([
    'unbounded' => [[], '0.0.1', true],
    'inclusive start hit' => [['version_incl_start' => '1.0'], '1.0.0', true],
    'inclusive start miss' => [['version_incl_start' => '1.0'], '0.9', false],
    'exclusive start at bound' => [['version_excl_start' => '1.0'], '1.0', false],
    'exclusive start above' => [['version_excl_start' => '1.0'], '1.0.1', true],
    'inclusive end at bound' => [['version_incl_end' => '2.0'], '2.0', true],
    'inclusive end above' => [['version_incl_end' => '2.0'], '2.0.1', false],
    'exclusive end at bound' => [['version_excl_end' => '2.0'], '2.0', false],
    'exclusive end below' => [['version_excl_end' => '2.0'], '2.0-rc1', true],
    'between both bounds' => [['version_incl_start' => '1.0', 'version_excl_end' => '1.5'], '1.4.9', true],
    'past both bounds' => [['version_incl_start' => '1.0', 'version_excl_end' => '1.5'], '1.5.0', false],
]);
