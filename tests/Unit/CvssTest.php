<?php

use App\Ingestion\Support\Cvss;

test('computes CVSS v3.1 base score and severity from a vector', function (string $vector, float $score, string $severity) {
    $cvss = Cvss::fromVector($vector);

    expect($cvss)->not->toBeNull();
    expect($cvss->version)->toBe('3.1');
    expect($cvss->vector)->toBe($vector);
    expect($cvss->baseScore)->toBe($score);
    expect($cvss->baseSeverity)->toBe($severity);
})->with([
    'critical, scope unchanged' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8, 'Critical'],
    'high, confidentiality only' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 7.5, 'High'],
    'medium, scope changed' => ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1, 'Medium'],
    'none' => ['CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N', 0.0, 'None'],
]);

test('computes CVSS v3.0 scores and keeps the 3.0 version', function () {
    $cvss = Cvss::fromVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');

    expect($cvss->version)->toBe('3.0');
    expect($cvss->baseScore)->toBe(9.8);
    expect($cvss->baseSeverity)->toBe('Critical');
});

test('computes CVSS v2.0 base score from an unprefixed vector', function () {
    $cvss = Cvss::fromVector('AV:N/AC:L/Au:N/C:P/I:P/A:P');

    expect($cvss->version)->toBe('2.0');
    expect($cvss->baseScore)->toBe(7.5);
    expect($cvss->baseSeverity)->toBe('High');
});

test('accepts a CVSS:2.0 prefixed vector', function () {
    expect(Cvss::fromVector('CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P')->version)->toBe('2.0');
});

test('scores a v4.0 vector', function (string $vector, float $score, string $severity) {
    $cvss = Cvss::fromVector($vector);

    expect($cvss->version)->toBe('4.0');
    expect($cvss->vector)->toBe($vector);
    expect($cvss->baseScore)->toBe($score);
    expect($cvss->baseSeverity)->toBe($severity);
})->with([
    'every impact on the vulnerable system' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 9.3, 'Critical'],
    'a single impact' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N', 8.7, 'High'],
    // worth 8.55 exactly, which computes as 8.549999999999999 in binary
    'a score on a rounding boundary' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H', 8.6, 'High'],
    'an unproven exploit' => ['CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U', 4.1, 'Medium'],
    'modified metrics replacing the base ones' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S', 10.0, 'Critical'],
    'no impact at all' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 0.0, 'None'],
]);

test('keeps version and vector but no score for an unreadable v4.0 vector', function (string $vector) {
    $cvss = Cvss::fromVector($vector);

    expect($cvss->version)->toBe('4.0');
    expect($cvss->baseScore)->toBeNull();
    expect($cvss->baseSeverity)->toBeNull();
})->with([
    'a missing base metric' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N'],
    'a value v4.0 does not define' => ['CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
]);

test('keeps version and vector but no score for an incomplete v3 vector', function () {
    $cvss = Cvss::fromVector('CVSS:3.1/AV:N/AC:L');

    expect($cvss->version)->toBe('3.1');
    expect($cvss->baseScore)->toBeNull();
    expect($cvss->baseSeverity)->toBeNull();
});

test('returns null for a string that is not a CVSS vector', function () {
    expect(Cvss::fromVector('HIGH'))->toBeNull();
    expect(Cvss::fromVector('not/a/vector'))->toBeNull();
});
