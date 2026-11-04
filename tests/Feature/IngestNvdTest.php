<?php

use App\Models\IngestRecord;
use App\Models\Source;
use App\Models\SyncState;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;

test('pulls the whole NVD catalog without a date range', function (?array $cursor, array $options) {
    $this->travelTo('2026-10-29 10:00:00');
    $source = Source::factory()->create(['slug' => 'nvd', 'ingest_base_url' => 'https://nvd.test/cves/2.0/']);
    if ($cursor !== null) {
        SyncState::create(['source_id' => $source->id, 'cursor' => $cursor]);
    }

    Sleep::fake();
    Http::preventStrayRequests();
    Http::fake([
        'nvd.test/cves/2.0*' => fn (Request $request) => Http::response([
            'totalResults' => 4000,
            'vulnerabilities' => [
                ['cve' => ['id' => $request->data()['startIndex'] === 0 ? 'CVE-2020-11738' : 'CVE-2022-21661']],
            ],
        ]),
    ]);

    $this->artisan('ingest:nvd', $options)->assertSuccessful();

    expect(Http::recorded()->map(fn (array $pair) => $pair[0]->data())->all())->toBe([
        ['resultsPerPage' => 2000, 'startIndex' => 0],
        ['resultsPerPage' => 2000, 'startIndex' => 2000],
    ]);
    expect(IngestRecord::where('source_id', $source->id)->orderBy('external_id')->pluck('external_id')->all())
        ->toBe(['CVE-2020-11738', 'CVE-2022-21661']);
    expect(SyncState::where('source_id', $source->id)->sole()->cursor)->toBe(['last_mod_end_date' => '2026-10-29T10:00:00.000Z']);
    Sleep::assertSleptTimes(2);
})->with([
    'on the first run' => [null, []],
    'with --full' => [['last_mod_end_date' => '2026-10-28T10:00:00.000Z'], ['--full' => true]],
]);

test('walks consecutive 120-day windows from a cursor older than 120 days', function () {
    $this->travelTo('2026-10-29 10:00:00');
    $source = Source::factory()->create(['slug' => 'nvd', 'ingest_base_url' => 'https://nvd.test/cves/2.0/']);
    SyncState::create(['source_id' => $source->id, 'cursor' => ['last_mod_end_date' => '2026-03-01T00:00:00.000Z']]);

    Sleep::fake();
    Http::preventStrayRequests();
    Http::fake([
        'nvd.test/cves/2.0*' => Http::response(['totalResults' => 0, 'vulnerabilities' => []]),
    ]);

    $this->artisan('ingest:nvd')->assertSuccessful();

    expect(Http::recorded()->map(fn (array $pair) => [$pair[0]['lastModStartDate'], $pair[0]['lastModEndDate']])->all())->toBe([
        ['2026-03-01T00:00:00.000Z', '2026-06-29T00:00:00.000Z'],
        ['2026-06-29T00:00:00.000Z', '2026-10-27T00:00:00.000Z'],
        ['2026-10-27T00:00:00.000Z', '2026-10-29T10:00:00.000Z'],
    ]);
    expect(SyncState::where('source_id', $source->id)->sole()->cursor)->toBe(['last_mod_end_date' => '2026-10-29T10:00:00.000Z']);
});
