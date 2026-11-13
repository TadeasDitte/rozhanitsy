<?php

namespace App\Ingestion\Support;

/**
 * The slug a platform's extension directory files a product under, as the
 * advisory links of a record name it. A WordPress plugin or theme is referenced
 * through wordpress.org, its plugin repository or the advisory database of the
 * CNA that filed the record, and the slug in those links is the directory the
 * extension is installed under, which is the name a scan reports it by.
 *
 * NVD's CPE name for such a product is often neither that slug nor a spelling
 * of it (`cleantalk-spam-protect` is filed as `cleantalk:spam_protection,
 * _antispam,_firewall`), and the CNA entry need not name the slug either, so
 * the links are the only place it appears.
 */
final readonly class PlatformSlug
{
    /** @var array<string, list<string>> the patterns naming an extension of each platform */
    private const array PATTERNS = [
        'wordpress' => [
            '~^(?:https?://)?(?:www\.)?wordpress\.org/(?:plugins|themes)/([^/?#]+)~i',
            '~^(?:https?://)?(?:plugins|themes)\.trac\.wordpress\.org/(?:changeset|browser|log|ticket)/\d+/([^/?#]+)~i',
            '~^(?:https?://)?(?:plugins|themes)\.trac\.wordpress\.org/\S*?(?:%40|@)([^/?#&%]+)~i',
            '~^(?:https?://)?(?:[a-z0-9-]+\.)?patchstack\.com/database/vulnerability/([^/?#]+)~i',
            '~^(?:https?://)?(?:[a-z0-9-]+\.)?patchstack\.com/database/wordpress/(?:plugin|theme)/([^/?#]+)~i',
            '~^(?:https?://)?(?:www\.)?wordfence\.com/threat-intel/vulnerabilities/wordpress-(?:plugins|themes)/([^/?#]+)~i',
            '~^(?:https?://)?(?:www\.)?wpscan\.com/(?:plugin|theme)/([^/?#]+)~i',
        ],
    ];

    /** @var list<string> paths of a directory that are not an extension */
    private const array RESERVED = ['search', 'browse', 'tags', 'tag', 'favorites', 'developers', 'about', 'blocks', 'upload', 'register'];

    /**
     * The one extension a record's links point at, and the platform it plugs
     * into. Links naming several extensions say nothing about which one the
     * record is about, a plugin's advisory may well link another plugin's page,
     * so those are read as naming none.
     *
     * @param  array<int, mixed>  $references  parsed_records.references
     * @return array{slug: string, platform: string}|null
     */
    public static function soleExtension(array $references): ?array
    {
        $extensions = [];

        foreach ($references as $reference) {
            $url = is_array($reference) ? ($reference['url'] ?? null) : null;

            if (! is_string($url)) {
                continue;
            }

            foreach (self::PATTERNS as $platform => $patterns) {
                foreach ($patterns as $pattern) {
                    if (preg_match($pattern, trim($url), $matches) !== 1) {
                        continue;
                    }

                    $slug = self::normalize($matches[1]);

                    if ($slug !== null) {
                        $extensions[$platform.'|'.$slug] = ['slug' => $slug, 'platform' => $platform];
                    }

                    continue 3;
                }
            }
        }

        return count($extensions) === 1 ? reset($extensions) : null;
    }

    /**
     * A slug as the directory spells it, or null when the path is not one.
     */
    private static function normalize(string $slug): ?string
    {
        $slug = trim(mb_strtolower(rawurldecode($slug)), '-._');

        return $slug !== '' && preg_match('/^[a-z0-9][a-z0-9._-]*$/', $slug) === 1 && ! in_array($slug, self::RESERVED, true)
            ? $slug
            : null;
    }
}
