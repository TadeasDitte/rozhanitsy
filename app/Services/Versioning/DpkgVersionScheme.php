<?php

namespace App\Services\Versioning;

/**
 * Debian policy 5.6.12: [epoch:]upstream[-revision], compared the way dpkg does.
 * Letters sort before other characters and "~" before everything, even the end
 * of the string, so 1.0~rc1 < 1.0.
 */
final class DpkgVersionScheme implements VersionScheme
{
    public function compare(string $a, string $b): int
    {
        [$epochA, $upstreamA, $revisionA] = $this->split($a);
        [$epochB, $upstreamB, $revisionB] = $this->split($b);

        return $this->compareNumbers($epochA, $epochB)
            ?: $this->compareFragment($upstreamA, $upstreamB)
            ?: $this->compareFragment($revisionA, $revisionB);
    }

    /**
     * @return array{string, string, string}
     */
    private function split(string $version): array
    {
        $version = trim($version);
        $epoch = '0';

        if (preg_match('/^(\d+):(.*)$/s', $version, $matches) === 1) {
            [, $epoch, $version] = $matches;
        }

        $hyphen = strrpos($version, '-');

        return $hyphen === false
            ? [$epoch, $version, '']
            : [$epoch, substr($version, 0, $hyphen), substr($version, $hyphen + 1)];
    }

    private function compareFragment(string $a, string $b): int
    {
        $i = $j = 0;
        $lengthA = strlen($a);
        $lengthB = strlen($b);

        while ($i < $lengthA || $j < $lengthB) {
            while (($i < $lengthA && ! ctype_digit($a[$i])) || ($j < $lengthB && ! ctype_digit($b[$j]))) {
                $orderA = $this->order($a[$i] ?? '');
                $orderB = $this->order($b[$j] ?? '');

                if ($orderA !== $orderB) {
                    return $orderA <=> $orderB;
                }

                $i++;
                $j++;
            }

            while ($i < $lengthA && $a[$i] === '0') {
                $i++;
            }

            while ($j < $lengthB && $b[$j] === '0') {
                $j++;
            }

            $firstDifference = 0;

            while ($i < $lengthA && ctype_digit($a[$i]) && $j < $lengthB && ctype_digit($b[$j])) {
                $firstDifference = $firstDifference ?: ord($a[$i]) - ord($b[$j]);
                $i++;
                $j++;
            }

            if ($i < $lengthA && ctype_digit($a[$i])) {
                return 1;
            }

            if ($j < $lengthB && ctype_digit($b[$j])) {
                return -1;
            }

            if ($firstDifference !== 0) {
                return $firstDifference <=> 0;
            }
        }

        return 0;
    }

    private function order(string $character): int
    {
        return match (true) {
            $character === '', ctype_digit($character) => 0,
            ctype_alpha($character) => ord($character),
            $character === '~' => -1,
            default => ord($character) + 256,
        };
    }

    private function compareNumbers(string $a, string $b): int
    {
        $a = ltrim($a, '0');
        $b = ltrim($b, '0');

        return (strlen($a) <=> strlen($b)) ?: (strcmp($a, $b) <=> 0);
    }
}
