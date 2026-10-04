<?php

namespace App\Services\Versioning;

interface VersionScheme
{
    /**
     * @return int -1 when $a < $b, 0 when equal, 1 when $a > $b
     */
    public function compare(string $a, string $b): int;
}
