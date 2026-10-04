<?php

use App\Models\VersionRange;
use Illuminate\Support\Facades\Cache;

test('serves a repeated check from cache until a parse run changes the data', function () {
    $range = VersionRange::factory()->create([
        'product' => 'lodash', 'version_incl_start' => null, 'version_excl_end' => '4.17.21',
    ]);
    $this->getJson(route('api.v1.check', ['product' => 'lodash', 'version' => '4.17.20']))
        ->assertJsonPath('data.vulnerable', true);
    $range->delete();

    $this->getJson(route('api.v1.check', ['product' => 'lodash', 'version' => '4.17.20']))
        ->assertJsonPath('data.vulnerable', true);
    $this->artisan('parse:l2')->assertSuccessful();

    $this->getJson(route('api.v1.check', ['product' => 'lodash', 'version' => '4.17.20']))
        ->assertJsonPath('data.vulnerable', false);
});

test('caches each checked version separately', function () {
    VersionRange::factory()->create([
        'product' => 'lodash', 'version_incl_start' => null, 'version_excl_end' => '4.17.21',
    ]);
    $this->getJson(route('api.v1.check', ['product' => 'lodash', 'version' => '4.17.20']));

    $this->getJson(route('api.v1.check', ['product' => 'lodash', 'version' => '4.17.21']))
        ->assertJsonPath('data.vulnerable', false);
});

test('serves a repeated product search from cache until a parse run changes the data', function () {
    VersionRange::factory()->create(['product' => 'openssl']);
    $this->getJson(route('api.v1.products.index', ['q' => 'openssl']))->assertJsonCount(1, 'data');
    VersionRange::query()->delete();

    $this->getJson(route('api.v1.products.index', ['q' => 'OpenSSL']))->assertJsonCount(1, 'data');
    $this->artisan('parse:fast')->assertSuccessful();

    $this->getJson(route('api.v1.products.index', ['q' => 'openssl']))->assertJsonCount(0, 'data');
});

test('serves the affected range as plain JSON from a serializing cache store', function () {
    config(['cache.stores.array.serialize' => true]);
    Cache::forgetDriver('array');
    VersionRange::factory()->create([
        'product' => 'lodash', 'version_incl_start' => null, 'version_excl_end' => '4.17.21',
    ]);
    $url = route('api.v1.check', ['product' => 'lodash', 'version' => '4.17.20']);

    $this->getJson($url)->assertJsonPath('data.vulnerabilities.0.affected_range.version_excl_end', '4.17.21');
    $this->getJson($url)
        ->assertJsonPath('data.vulnerabilities.0.affected_range.version_excl_end', '4.17.21')
        ->assertJsonMissingPath('data.vulnerabilities.0.affected_range.__PHP_Incomplete_Class_Name');
});
