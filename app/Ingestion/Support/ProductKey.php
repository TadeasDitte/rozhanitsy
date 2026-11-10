<?php

namespace App\Ingestion\Support;

/**
 * A product name reduced to its letters and digits, so that spellings differing
 * only in punctuation count as one name: the WordPress plugin slug `jet-engine`
 * and the slug of the CNA's product name "JetEngine" both key to `jetengine`.
 */
final readonly class ProductKey
{
    public static function for(?string $name): ?string
    {
        if ($name === null) {
            return null;
        }

        $key = preg_replace('/[^a-z0-9]+/', '', mb_strtolower($name)) ?? '';

        return $key !== '' ? $key : null;
    }
}
