<?php

namespace App\Services\Versioning;

/**
 * [epoch:]version[-release] compared with rpmvercmp: alphanumeric segments,
 * numbers newer than letters, "~" sorting before the end, "^" after it.
 * A release is only compared when both sides have one.
 */
final class RpmVersionScheme implements VersionScheme
{
    public function compare(string $a, string $b): int
    {
        [$epochA, $versionA, $releaseA] = $this->split($a);
        [$epochB, $versionB, $releaseB] = $this->split($b);

        $result = $this->compareNumbers($epochA, $epochB) ?: $this->segments($versionA, $versionB);

        if ($result === 0 && $releaseA !== null && $releaseB !== null) {
            return $this->segments($releaseA, $releaseB);
        }

        return $result;
    }

    /**
     * @return array{string, string, ?string}
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
            ? [$epoch, $version, null]
            : [$epoch, substr($version, 0, $hyphen), substr($version, $hyphen + 1)];
    }

    private function segments(string $one, string $two): int
    {
        if ($one === $two) {
            return 0;
        }

        $i = $j = 0;
        $lengthOne = strlen($one);
        $lengthTwo = strlen($two);

        while ($i < $lengthOne || $j < $lengthTwo) {
            while ($i < $lengthOne && ! $this->isSegmentCharacter($one[$i])) {
                $i++;
            }

            while ($j < $lengthTwo && ! $this->isSegmentCharacter($two[$j])) {
                $j++;
            }

            $first = $one[$i] ?? '';
            $second = $two[$j] ?? '';

            if ($first === '~' || $second === '~') {
                if ($first !== '~') {
                    return 1;
                }

                if ($second !== '~') {
                    return -1;
                }

                $i++;
                $j++;

                continue;
            }

            if ($first === '^' || $second === '^') {
                if ($first === '') {
                    return -1;
                }

                if ($second === '') {
                    return 1;
                }

                if ($first !== '^') {
                    return 1;
                }

                if ($second !== '^') {
                    return -1;
                }

                $i++;
                $j++;

                continue;
            }

            if ($first === '' || $second === '') {
                break;
            }

            $isNumeric = ctype_digit($first);
            $startOne = $i;
            $startTwo = $j;
            $matches = $isNumeric ? ctype_digit(...) : ctype_alpha(...);

            while ($i < $lengthOne && $matches($one[$i])) {
                $i++;
            }

            while ($j < $lengthTwo && $matches($two[$j])) {
                $j++;
            }

            if ($j === $startTwo) {
                return $isNumeric ? 1 : -1;
            }

            $segmentOne = substr($one, $startOne, $i - $startOne);
            $segmentTwo = substr($two, $startTwo, $j - $startTwo);

            if ($isNumeric) {
                $result = $this->compareNumbers($segmentOne, $segmentTwo);
            } else {
                $result = strcmp($segmentOne, $segmentTwo) <=> 0;
            }

            if ($result !== 0) {
                return $result;
            }
        }

        if ($i >= $lengthOne && $j >= $lengthTwo) {
            return 0;
        }

        return $i < $lengthOne ? 1 : -1;
    }

    private function isSegmentCharacter(string $character): bool
    {
        return ctype_alnum($character) || $character === '~' || $character === '^';
    }

    private function compareNumbers(string $a, string $b): int
    {
        $a = ltrim($a, '0');
        $b = ltrim($b, '0');

        return (strlen($a) <=> strlen($b)) ?: (strcmp($a, $b) <=> 0);
    }
}
