<?php

use App\Services\Versioning\DpkgVersionScheme;

test('orders dpkg versions', function (string $lower, string $higher) {
    $scheme = new DpkgVersionScheme;

    expect($scheme->compare($lower, $higher))->toBe(-1)
        ->and($scheme->compare($higher, $lower))->toBe(1);
})->with([
    'upstream then revision' => ['1.0-1', '2.0-2'],
    'tilde before the release' => ['1.0~rc1-1', '1.0-1'],
    'tilde before the end of the string' => ['2.2~rc-4', '2.2-1'],
    'double tilde before single tilde' => ['0foo~~', '0foo~'],
    'tilde before nothing' => ['1~', '1'],
    'letters after the bare release' => ['1.0-1', '1.0rc1-1'],
    'epoch wins over upstream' => ['9.9', '1:0.1'],
    'higher epoch wins' => ['1:9.9', '2:1.0'],
    'numeric revision parts' => ['3.0.13-0ubuntu3.5', '3.0.13-0ubuntu3.16'],
    'numeric upstream parts' => ['1.0.8', '1.0.10'],
    'plus after the bare release' => ['1.0.8', '1.0.8+nmu1'],
    'letters before other characters' => ['0foo-0', '0foo+-0'],
    'uppercase before lowercase' => ['0foo~foo+Bar', '0foo~foo+bar'],
    'last hyphen starts the revision' => ['1.0-1-1', '1.0-1-2'],
    'colon stays in the upstream version' => ['0:1:0', '0:1:1'],
]);

test('treats equivalent dpkg spellings as equal', function (string $a, string $b) {
    expect((new DpkgVersionScheme)->compare($a, $b))->toBe(0);
})->with([
    'leading zeros' => ['1.09', '1.9'],
    'zero padded revision' => ['1.0000-1', '1.0-1'],
    'implicit epoch' => ['1', '0:1'],
    'implicit zero epoch and revision' => ['0', '0:0-0'],
    'missing revision' => ['0foo', '0foo-0'],
]);
