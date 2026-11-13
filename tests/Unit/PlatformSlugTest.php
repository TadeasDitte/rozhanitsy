<?php

use App\Ingestion\Support\PlatformSlug;

/**
 * @param  list<string>  $urls
 * @return array<int, array{url: string, tags: array<int, string>}>
 */
function platformReferences(array $urls): array
{
    return array_map(fn (string $url): array => ['url' => $url, 'tags' => []], $urls);
}

test('reads the WordPress extension a link names', function (string $url, string $slug) {
    expect(PlatformSlug::soleExtension(platformReferences([$url])))->toBe(['slug' => $slug, 'platform' => 'wordpress']);
})->with([
    'a plugin directory page' => ['https://wordpress.org/plugins/metform/#description', 'metform'],
    'a theme directory page' => ['https://wordpress.org/themes/kopa/', 'kopa'],
    'a repository changeset' => ['https://plugins.trac.wordpress.org/changeset/2711944/metform/trunk/core/forms/action.php', 'metform'],
    'a changeset named in the query' => ['https://plugins.trac.wordpress.org/changeset?sfp_email=&old=2868889%40metform&new=2868889%40metform', 'metform'],
    'a Patchstack advisory' => ['https://patchstack.com/database/vulnerability/sunshine-photo-cart/wordpress-sunshine-photo-cart-plugin-2-9-13-', 'sunshine-photo-cart'],
    'a Patchstack plugin page' => ['https://vdp.patchstack.com/database/wordpress/plugin/sliderspack-all-in-one-image-sliders/vulnerability/x', 'sliderspack-all-in-one-image-sliders'],
    'a Wordfence plugin advisory' => ['https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/metform/x', 'metform'],
    'a WPScan plugin advisory' => ['https://wpscan.com/plugin/metform/', 'metform'],
]);

test('reads one extension from links naming it in several shapes', function () {
    $slug = PlatformSlug::soleExtension(platformReferences([
        'https://wordpress.org/plugins/metform/',
        'https://plugins.trac.wordpress.org/changeset/2711944/metform/trunk/core/forms/action.php',
        'https://patchstack.com/database/vulnerability/metform/wordpress-metform-plugin-3-7-6',
    ]));

    expect($slug)->toBe(['slug' => 'metform', 'platform' => 'wordpress']);
});

test('reads no extension from links that name none of one', function (array $urls) {
    expect(PlatformSlug::soleExtension(platformReferences($urls)))->toBeNull();
})->with([
    'an advisory by its own id' => [['https://www.wordfence.com/threat-intel/vulnerabilities/id/04a46249-b5b2-4082-b520-cdc4a1370bb1?source=cve']],
    'a WPScan vulnerability id' => [['https://wpscan.com/vulnerability/54c1251f-96be-4d70-b773-3db26b599838/']],
    'a directory listing page' => [['https://wordpress.org/plugins/search/forms/', 'https://wordpress.org/plugins/browse/popular/']],
    'a WordPress page that is not the directory' => [['https://wordpress.org/news/2026/01/release/', 'https://developer.wordpress.org/plugins/']],
    'two extensions' => [['https://wordpress.org/plugins/metform/', 'https://wordpress.org/plugins/woocommerce/']],
    'no links at all' => [[]],
]);

test('reads no extension from references that hold no URL', function () {
    expect(PlatformSlug::soleExtension([['tags' => ['Product']], ['url' => null]]))->toBeNull();
});
