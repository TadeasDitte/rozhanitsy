<?php

namespace App\Ingestion\Support;

/**
 * A CVSS severity band, whatever the source reporting it calls it. GitHub's
 * advisory database names the medium band "moderate", NVD and CVSS name it
 * "medium", and the sources capitalise as they please.
 */
final readonly class Severity
{
    /** @var array<string, string> the band each alternative name belongs to */
    private const array ALIASES = ['moderate' => 'medium'];

    /**
     * The band's name as a parsed record stores it, in the title case OSV records
     * are stored with.
     */
    public static function label(string $severity): string
    {
        return ucfirst(self::band($severity));
    }

    /**
     * The band a filter names, to compare case insensitively with a stored
     * severity: NVD writes `CRITICAL`, OSV `Critical`.
     */
    public static function forFilter(string $severity): string
    {
        return strtoupper(self::band($severity));
    }

    private static function band(string $severity): string
    {
        $name = mb_strtolower(trim($severity));

        return self::ALIASES[$name] ?? $name;
    }
}
