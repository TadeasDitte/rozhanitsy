<?php

use App\Models\IngestRecord;
use App\Models\Source;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

test('downloads all.zip with no total time limit, aborting only stalled transfers', function () {
    $source = Source::factory()->create(['slug' => 'osv', 'ingest_base_url' => 'https://osv.test']);

    $zipPath = tempnam(sys_get_temp_dir(), 'osv');
    $zip = new ZipArchive;
    $zip->open($zipPath, ZipArchive::OVERWRITE);
    $zip->addFromString('GHSA-a.json', json_encode(['id' => 'GHSA-a']));
    $zip->close();
    $zipContents = file_get_contents($zipPath);
    unlink($zipPath);

    $downloadOptions = null;
    Http::preventStrayRequests();
    Http::fake([
        'osv.test/all.zip' => function (Request $request, array $options) use (&$downloadOptions, $zipContents) {
            $downloadOptions = $options;

            return Http::response($zipContents);
        },
    ]);

    $this->artisan('ingest:osv')->assertSuccessful();

    expect($downloadOptions['timeout'])->toBe(0);
    expect($downloadOptions['connect_timeout'])->toBeGreaterThan(0);
    expect($downloadOptions['curl'])->toHaveKeys([CURLOPT_LOW_SPEED_LIMIT, CURLOPT_LOW_SPEED_TIME]);
    expect(IngestRecord::where('source_id', $source->id)->pluck('external_id')->all())->toBe(['GHSA-a']);
});
