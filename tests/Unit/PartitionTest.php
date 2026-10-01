<?php

use App\Ingestion\Partition;

test('parses the INDEX/COUNT option form', function () {
    $partition = Partition::fromOption('2/4');

    expect($partition->index)->toBe(2);
    expect($partition->count)->toBe(4);
    expect($partition->toOption())->toBe('2/4');
});

test('an empty option means no partition', function (?string $value) {
    expect(Partition::fromOption($value))->toBeNull();
})->with([null, '']);

test('rejects malformed or out-of-range partitions', function (string $value) {
    Partition::fromOption($value);
})->throws(InvalidArgumentException::class)->with(['abc', '1', '-1/2', '2/2', '0/0']);
