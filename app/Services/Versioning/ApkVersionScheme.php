<?php

namespace App\Services\Versioning;

/**
 * Alpine apk versions: numbers joined by dots, an optional letter, suffixes such
 * as _rc1 (pre-release) or _p1 (post-release) and a -r revision. Walks both
 * versions token by token like apk-tools does, including its rule that a
 * component with leading zeros sorts before one without.
 */
final class ApkVersionScheme implements VersionScheme
{
    private const int DIGIT_OR_ZERO = 0;

    private const int DIGIT = 1;

    private const int LETTER = 2;

    private const int SUFFIX = 3;

    private const int SUFFIX_NUMBER = 4;

    private const int REVISION_NUMBER = 5;

    private const int END = 6;

    private const int INVALID = -1;

    private const array PRE_SUFFIXES = ['alpha', 'beta', 'pre', 'rc'];

    private const array POST_SUFFIXES = ['cvs', 'svn', 'git', 'hg', 'p'];

    public function compare(string $a, string $b): int
    {
        $a = trim($a);
        $b = trim($b);
        $typeA = $typeB = self::DIGIT;
        $valueA = $valueB = 0;

        while ($typeA === $typeB && $typeA !== self::END && $typeA !== self::INVALID && $valueA === $valueB) {
            $valueA = $this->token($typeA, $a);
            $valueB = $this->token($typeB, $b);
        }

        if ($valueA !== $valueB) {
            return $valueA <=> $valueB;
        }

        if ($typeA === $typeB) {
            return 0;
        }

        if ($typeA === self::SUFFIX && $this->token($typeA, $a) < 0) {
            return -1;
        }

        if ($typeB === self::SUFFIX && $this->token($typeB, $b) < 0) {
            return 1;
        }

        return $typeB <=> $typeA;
    }

    /**
     * Reads the token of the given type from the front of $rest and sets $type
     * to the type of the token that follows.
     */
    private function token(int &$type, string &$rest): int
    {
        if ($rest === '') {
            $type = self::END;

            return 0;
        }

        $length = strlen($rest);
        $consumed = 0;
        $value = 0;
        $next = self::INVALID;

        switch ($type) {
            case self::DIGIT_OR_ZERO:
                if ($rest[0] === '0') {
                    while ($consumed < $length && $rest[$consumed] === '0') {
                        $consumed++;
                    }

                    $next = self::DIGIT;
                    $value = -$consumed;

                    break;
                }

                // no break
            case self::DIGIT:
            case self::SUFFIX_NUMBER:
            case self::REVISION_NUMBER:
                while ($consumed < $length && ctype_digit($rest[$consumed])) {
                    $value = $value * 10 + (int) $rest[$consumed];
                    $consumed++;
                }

                break;
            case self::LETTER:
                $value = ord($rest[0]);
                $consumed = 1;

                break;
            case self::SUFFIX:
                $suffix = $this->suffix($rest);

                if ($suffix === null) {
                    $type = self::INVALID;

                    return -1;
                }

                [$value, $consumed] = $suffix;

                break;
            default:
                $type = self::INVALID;

                return -1;
        }

        $rest = substr($rest, $consumed);
        $type = $next !== self::INVALID ? $next : $this->nextType($type, $rest);

        return $value;
    }

    /**
     * @return array{int, int}|null the rank (negative for pre-releases) and the length of the suffix
     */
    private function suffix(string $rest): ?array
    {
        foreach (self::PRE_SUFFIXES as $rank => $name) {
            if (str_starts_with($rest, $name)) {
                return [$rank - count(self::PRE_SUFFIXES), strlen($name)];
            }
        }

        foreach (self::POST_SUFFIXES as $rank => $name) {
            if (str_starts_with($rest, $name)) {
                return [$rank, strlen($name)];
            }
        }

        return null;
    }

    private function nextType(int $type, string &$rest): int
    {
        if ($type === self::SUFFIX) {
            return self::SUFFIX_NUMBER;
        }

        if ($rest === '') {
            return self::END;
        }

        if ($type === self::REVISION_NUMBER) {
            return self::INVALID;
        }

        $character = $rest[0];

        if (($type === self::DIGIT_OR_ZERO || $type === self::DIGIT) && $character === '.') {
            $rest = substr($rest, 1);

            return self::DIGIT_OR_ZERO;
        }

        if (($type === self::DIGIT_OR_ZERO || $type === self::DIGIT) && ctype_lower($character)) {
            return self::LETTER;
        }

        if ($character === '_') {
            $rest = substr($rest, 1);

            return self::SUFFIX;
        }

        if ($character === '-' && ($rest[1] ?? '') === 'r') {
            $rest = substr($rest, 2);

            return self::REVISION_NUMBER;
        }

        return self::INVALID;
    }
}
