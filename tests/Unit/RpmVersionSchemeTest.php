<?php

use App\Services\Versioning\RpmVersionScheme;

test('orders rpm versions', function (string $lower, string $higher) {
    $scheme = new RpmVersionScheme;

    expect($scheme->compare($lower, $higher))->toBe(-1)
        ->and($scheme->compare($higher, $lower))->toBe(1);
})->with([
    'numeric not lexical' => ['5.5p1', '5.5p10'],
    'longer release' => ['2.0', '2.0.1'],
    'letters before numbers' => ['xyz.4', '8'],
    'longer letter run' => ['1.0a', '1.0aa'],
    'tilde before the release' => ['1.0~rc1', '1.0'],
    'tilde order' => ['1.0~rc1', '1.0~rc2'],
    'tilde before a tilde suffix' => ['1.0~rc1~git123', '1.0~rc1'],
    'caret after the release' => ['1.0', '1.0^git1'],
    'caret before the next number' => ['1.0^git1', '1.01'],
    'caret snapshot before the next release' => ['1.0^20160101', '1.0.1'],
    'caret after tilde' => ['1.0~rc1', '1.0~rc1^git1'],
    'release compared' => ['1.2-3.el9', '1.2-10.el9'],
    'release with a minor' => ['1.2-3.el9', '1.2-3.el9_2'],
    'epoch wins over version' => ['0:9.9', '1:1.0'],
    'implicit epoch' => ['9.9-1', '1:0.1-1'],
]);

test('treats equivalent rpm spellings as equal', function (string $a, string $b) {
    expect((new RpmVersionScheme)->compare($a, $b))->toBe(0);
})->with([
    'separators are ignored' => ['2.0', '2_0'],
    'leading zeros' => ['10.0001', '10.1'],
    'implicit epoch' => ['1.2-3', '0:1.2-3'],
    'release only compared when both have one' => ['1.2-3.el9', '1.2'],
]);
