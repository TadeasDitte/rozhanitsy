<?php

use App\Services\Versioning\ApkVersionScheme;

test('orders apk versions', function (string $lower, string $higher) {
    $scheme = new ApkVersionScheme;

    expect($scheme->compare($lower, $higher))->toBe(-1)
        ->and($scheme->compare($higher, $lower))->toBe(1);
})->with([
    'numeric not lexical' => ['1.2.3', '1.2.10'],
    'longer release' => ['1.0', '1.0.1'],
    'pre-release before the release' => ['1.0_rc1', '1.0'],
    'pre-release order' => ['1.0_alpha', '1.0_beta'],
    'pre-release number' => ['1.0_rc1', '1.0_rc2'],
    'pre-release before a later release' => ['1.0_alpha', '1.0.1'],
    'post-release after the release' => ['1.0', '1.0_p1'],
    'letter after the release' => ['1.0', '1.0a'],
    'letters ordered' => ['1.0a', '1.0b'],
    'revision after the release' => ['1.0', '1.0-r1'],
    'revision order' => ['1.0-r1', '1.0-r2'],
    'numeric revision' => ['3.1.4-r9', '3.1.4-r10'],
    'revision before the next release' => ['1.3.1-r2', '1.3.2-r0'],
    'leading zeros sort first' => ['1.01', '1.1'],
    'suffix beats the revision' => ['1.0_rc1-r5', '1.0-r0'],
]);

test('treats identical apk versions as equal', function (string $a, string $b) {
    expect((new ApkVersionScheme)->compare($a, $b))->toBe(0);
})->with([
    'pre-release' => ['0.1.0_alpha', '0.1.0_alpha'],
    'revision' => ['2.16.1-r3', '2.16.1-r3'],
]);
