<?php

use App\Ingestion\Partition;

test('parses the FIRST_ID-LAST_ID option form', function () {
    $partition = Partition::fromOption('100-250');

    expect($partition->firstId)->toBe(100);
    expect($partition->lastId)->toBe(250);
    expect($partition->toOption())->toBe('100-250');
});

test('an empty option means no partition', function (?string $value) {
    expect(Partition::fromOption($value))->toBeNull();
})->with([null, '']);

test('rejects malformed or inverted partitions', function (string $value) {
    Partition::fromOption($value);
})->throws(InvalidArgumentException::class)->with(['abc', '1', '1/2', '-1-2', '5-4']);
