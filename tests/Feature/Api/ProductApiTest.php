<?php

use App\Models\ParsedRecord;
use App\Models\VersionRange;

test('finds products by name prefix with their vulnerability counts', function () {
    $record = ParsedRecord::factory()->create();
    VersionRange::factory()->count(2)->for($record)->create(['vendor' => 'openssl', 'product' => 'openssl']);
    VersionRange::factory()->create(['vendor' => 'openssl', 'product' => 'openssl']);
    VersionRange::factory()->create(['vendor' => 'nginx', 'product' => 'nginx']);

    $this->getJson(route('api.v1.products.index', ['q' => 'OpenS']))
        ->assertOk()
        ->assertExactJson(['data' => [
            ['vendor' => 'openssl', 'product' => 'openssl', 'ecosystem' => null, 'vulnerability_count' => 2],
        ]]);
});

test('narrows products by ecosystem', function () {
    VersionRange::factory()->create(['product' => 'lodash', 'ecosystem' => 'npm']);
    VersionRange::factory()->create(['product' => 'lodash-py', 'ecosystem' => 'PyPI']);

    $this->getJson(route('api.v1.products.index', ['q' => 'lodash', 'ecosystem' => 'npm']))
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.ecosystem', 'npm');
});

test('requires a search term of at least two characters', function () {
    $this->getJson(route('api.v1.products.index', ['q' => 'a']))
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['q']);
});
