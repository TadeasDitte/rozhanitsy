<?php

namespace App\Ingestion\Support;

/**
 * The base score of a CVSS v4.0 vector.
 *
 * v4.0 scores are not a formula. The specification sorts every vector into one
 * of 270 "MacroVector" equivalence classes, gives each class a score, and then
 * interpolates: the vector loses a share of the distance to the next lower
 * class, in proportion to how far it sits from the most severe vector of its
 * own class. The lookup table and the constants below are FIRST's own, from
 * the reference calculator at https://github.com/FIRSTdotorg/cvss-v4-calculator
 * (BSD-2-Clause), and this is a port of its cvss_score() and macroVector().
 */
final readonly class CvssV4
{
    /** The base metrics a vector must carry to be scored at all. */
    private const array BASE_METRICS = ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

    /** The impact metrics that score 0.0 when none of them is affected. */
    private const array IMPACT_METRICS = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA'];

    /** @var array<string, float> the score of each MacroVector */
    private const array LOOKUP = [
        '000000' => 10.0, '000001' => 9.9, '000010' => 9.8, '000011' => 9.5, '000020' => 9.5,
        '000021' => 9.2, '000100' => 10.0, '000101' => 9.6, '000110' => 9.3, '000111' => 8.7,
        '000120' => 9.1, '000121' => 8.1, '000200' => 9.3, '000201' => 9.0, '000210' => 8.9,
        '000211' => 8.0, '000220' => 8.1, '000221' => 6.8, '001000' => 9.8, '001001' => 9.5,
        '001010' => 9.5, '001011' => 9.2, '001020' => 9.0, '001021' => 8.4, '001100' => 9.3,
        '001101' => 9.2, '001110' => 8.9, '001111' => 8.1, '001120' => 8.1, '001121' => 6.5,
        '001200' => 8.8, '001201' => 8.0, '001210' => 7.8, '001211' => 7.0, '001220' => 6.9,
        '001221' => 4.8, '002001' => 9.2, '002011' => 8.2, '002021' => 7.2, '002101' => 7.9,
        '002111' => 6.9, '002121' => 5.0, '002201' => 6.9, '002211' => 5.5, '002221' => 2.7,
        '010000' => 9.9, '010001' => 9.7, '010010' => 9.5, '010011' => 9.2, '010020' => 9.2,
        '010021' => 8.5, '010100' => 9.5, '010101' => 9.1, '010110' => 9.0, '010111' => 8.3,
        '010120' => 8.4, '010121' => 7.1, '010200' => 9.2, '010201' => 8.1, '010210' => 8.2,
        '010211' => 7.1, '010220' => 7.2, '010221' => 5.3, '011000' => 9.5, '011001' => 9.3,
        '011010' => 9.2, '011011' => 8.5, '011020' => 8.5, '011021' => 7.3, '011100' => 9.2,
        '011101' => 8.2, '011110' => 8.0, '011111' => 7.2, '011120' => 7.0, '011121' => 5.9,
        '011200' => 8.4, '011201' => 7.0, '011210' => 7.1, '011211' => 5.2, '011220' => 5.0,
        '011221' => 3.0, '012001' => 8.6, '012011' => 7.5, '012021' => 5.2, '012101' => 7.1,
        '012111' => 5.2, '012121' => 2.9, '012201' => 6.3, '012211' => 2.9, '012221' => 1.7,
        '100000' => 9.8, '100001' => 9.5, '100010' => 9.4, '100011' => 8.7, '100020' => 9.1,
        '100021' => 8.1, '100100' => 9.4, '100101' => 8.9, '100110' => 8.6, '100111' => 7.4,
        '100120' => 7.7, '100121' => 6.4, '100200' => 8.7, '100201' => 7.5, '100210' => 7.4,
        '100211' => 6.3, '100220' => 6.3, '100221' => 4.9, '101000' => 9.4, '101001' => 8.9,
        '101010' => 8.8, '101011' => 7.7, '101020' => 7.6, '101021' => 6.7, '101100' => 8.6,
        '101101' => 7.6, '101110' => 7.4, '101111' => 5.8, '101120' => 5.9, '101121' => 5.0,
        '101200' => 7.2, '101201' => 5.7, '101210' => 5.7, '101211' => 5.2, '101220' => 5.2,
        '101221' => 2.5, '102001' => 8.3, '102011' => 7.0, '102021' => 5.4, '102101' => 6.5,
        '102111' => 5.8, '102121' => 2.6, '102201' => 5.3, '102211' => 2.1, '102221' => 1.3,
        '110000' => 9.5, '110001' => 9.0, '110010' => 8.8, '110011' => 7.6, '110020' => 7.6,
        '110021' => 7.0, '110100' => 9.0, '110101' => 7.7, '110110' => 7.5, '110111' => 6.2,
        '110120' => 6.1, '110121' => 5.3, '110200' => 7.7, '110201' => 6.6, '110210' => 6.8,
        '110211' => 5.9, '110220' => 5.2, '110221' => 3.0, '111000' => 8.9, '111001' => 7.8,
        '111010' => 7.6, '111011' => 6.7, '111020' => 6.2, '111021' => 5.8, '111100' => 7.4,
        '111101' => 5.9, '111110' => 5.7, '111111' => 5.7, '111120' => 4.7, '111121' => 2.3,
        '111200' => 6.1, '111201' => 5.2, '111210' => 5.7, '111211' => 2.9, '111220' => 2.4,
        '111221' => 1.6, '112001' => 7.1, '112011' => 5.9, '112021' => 3.0, '112101' => 5.8,
        '112111' => 2.6, '112121' => 1.5, '112201' => 2.3, '112211' => 1.3, '112221' => 0.6,
        '200000' => 9.3, '200001' => 8.7, '200010' => 8.6, '200011' => 7.2, '200020' => 7.5,
        '200021' => 5.8, '200100' => 8.6, '200101' => 7.4, '200110' => 7.4, '200111' => 6.1,
        '200120' => 5.6, '200121' => 3.4, '200200' => 7.0, '200201' => 5.4, '200210' => 5.2,
        '200211' => 4.0, '200220' => 4.0, '200221' => 2.2, '201000' => 8.5, '201001' => 7.5,
        '201010' => 7.4, '201011' => 5.5, '201020' => 6.2, '201021' => 5.1, '201100' => 7.2,
        '201101' => 5.7, '201110' => 5.5, '201111' => 4.1, '201120' => 4.6, '201121' => 1.9,
        '201200' => 5.3, '201201' => 3.6, '201210' => 3.4, '201211' => 1.9, '201220' => 1.9,
        '201221' => 0.8, '202001' => 6.4, '202011' => 5.1, '202021' => 2.0, '202101' => 4.7,
        '202111' => 2.1, '202121' => 1.1, '202201' => 2.4, '202211' => 0.9, '202221' => 0.4,
        '210000' => 8.8, '210001' => 7.5, '210010' => 7.3, '210011' => 5.3, '210020' => 6.0,
        '210021' => 5.0, '210100' => 7.3, '210101' => 5.5, '210110' => 5.9, '210111' => 4.0,
        '210120' => 4.1, '210121' => 2.0, '210200' => 5.4, '210201' => 4.3, '210210' => 4.5,
        '210211' => 2.2, '210220' => 2.0, '210221' => 1.1, '211000' => 7.5, '211001' => 5.5,
        '211010' => 5.8, '211011' => 4.5, '211020' => 4.0, '211021' => 2.1, '211100' => 6.1,
        '211101' => 5.1, '211110' => 4.8, '211111' => 1.8, '211120' => 2.0, '211121' => 0.9,
        '211200' => 4.6, '211201' => 1.8, '211210' => 1.7, '211211' => 0.7, '211220' => 0.8,
        '211221' => 0.2, '212001' => 5.3, '212011' => 2.4, '212021' => 1.4, '212101' => 2.4,
        '212111' => 1.2, '212121' => 0.5, '212201' => 1.0, '212211' => 0.3, '212221' => 0.1,
    ];

    /** @var array<string, array<string, float>> how severe each value of a metric is, lower being worse */
    private const array LEVELS = [
        'AV' => ['N' => 0.0, 'A' => 0.1, 'L' => 0.2, 'P' => 0.3],
        'PR' => ['N' => 0.0, 'L' => 0.1, 'H' => 0.2],
        'UI' => ['N' => 0.0, 'P' => 0.1, 'A' => 0.2],
        'AC' => ['L' => 0.0, 'H' => 0.1],
        'AT' => ['N' => 0.0, 'P' => 0.1],
        'VC' => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        'VI' => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        'VA' => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        'SC' => ['H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        'SI' => ['S' => 0.0, 'H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        'SA' => ['S' => 0.0, 'H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        'CR' => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
        'IR' => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
        'AR' => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
        'E' => ['A' => 0.0, 'P' => 0.1, 'U' => 0.2],
    ];

    /** @var array<string, mixed> the most severe vectors of each equivalence class */
    private const array MAX_COMPOSED = [
        'eq1' => [
            0 => ['AV:N/PR:N/UI:N/'],
            1 => ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
            2 => ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/'],
        ],
        'eq2' => [
            0 => ['AC:L/AT:N/'],
            1 => ['AC:H/AT:N/', 'AC:L/AT:P/'],
        ],
        'eq3' => [
            0 => [
                0 => ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
                1 => ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/'],
            ],
            1 => [
                0 => ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
                1 => ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/', 'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/', 'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/'],
            ],
            2 => [
                1 => ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/'],
            ],
        ],
        'eq4' => [
            0 => ['SC:H/SI:S/SA:S/'],
            1 => ['SC:H/SI:H/SA:H/'],
            2 => ['SC:L/SI:L/SA:L/'],
        ],
        'eq5' => [
            0 => ['E:A/'],
            1 => ['E:P/'],
            2 => ['E:U/'],
        ],
    ];

    /** @var array<string, mixed> the depth of each equivalence class, in steps of 0.1 */
    private const array MAX_SEVERITY = [
        'eq1' => [0 => 1, 1 => 4, 2 => 5],
        'eq2' => [0 => 1, 1 => 2],
        'eq3eq6' => [0 => [0 => 7, 1 => 6], 1 => [0 => 8, 1 => 8], 2 => [1 => 10]],
        'eq4' => [0 => 6, 1 => 5, 2 => 4],
        'eq5' => [0 => 1, 1 => 1, 2 => 1],
    ];

    /**
     * Null when the vector lacks a base metric or gives one a value v4.0 does not
     * define, which is how an unreadable v3 vector is treated too.
     *
     * @param  array<string, string>  $metrics
     */
    public static function score(array $metrics): ?float
    {
        foreach (self::BASE_METRICS as $metric) {
            if (! isset($metrics[$metric])) {
                return null;
            }
        }

        $resolved = self::resolve($metrics);

        if ($resolved === null) {
            return null;
        }

        foreach (self::IMPACT_METRICS as $metric) {
            if ($resolved[$metric] !== 'N') {
                return self::interpolate($resolved, self::macroVector($resolved, $metrics));
            }
        }

        return 0.0;
    }

    /**
     * Every metric the score reads, with the values the specification puts in
     * place of a missing or explicitly undefined (`X`) one: an undefined
     * exploit maturity counts as attacked, an undefined requirement as high,
     * and a modified metric replaces the base metric it modifies.
     *
     * @param  array<string, string>  $metrics
     * @return array<string, string>|null null when a value is not one v4.0 defines
     */
    private static function resolve(array $metrics): ?array
    {
        $resolved = [];

        foreach (self::LEVELS as $metric => $levels) {
            $value = $metrics[$metric] ?? 'X';

            if ($metric === 'E' && $value === 'X') {
                $value = 'A';
            } elseif (in_array($metric, ['CR', 'IR', 'AR'], true) && $value === 'X') {
                $value = 'H';
            } elseif (($metrics['M'.$metric] ?? 'X') !== 'X') {
                $value = $metrics['M'.$metric];
            }

            if (! isset($levels[$value])) {
                return null;
            }

            $resolved[$metric] = $value;
        }

        return $resolved;
    }

    /**
     * The six equivalence classes the vector falls into, as one string. The
     * subsequent system class (EQ4) is the only one that reads a modified
     * metric directly: only an explicit MSI:S or MSA:S makes a system safety
     * impact.
     *
     * @param  array<string, string>  $resolved
     * @param  array<string, string>  $metrics
     */
    private static function macroVector(array $resolved, array $metrics): string
    {
        $isNone = fn (string $metric): bool => $resolved[$metric] === 'N';
        $isHigh = fn (string $metric): bool => $resolved[$metric] === 'H';

        $eq1 = match (true) {
            $isNone('AV') && $isNone('PR') && $isNone('UI') => 0,
            ($isNone('AV') || $isNone('PR') || $isNone('UI')) && $resolved['AV'] !== 'P' => 1,
            default => 2,
        };

        $eq2 = $resolved['AC'] === 'L' && $isNone('AT') ? 0 : 1;

        $eq3 = match (true) {
            $isHigh('VC') && $isHigh('VI') => 0,
            $isHigh('VC') || $isHigh('VI') || $isHigh('VA') => 1,
            default => 2,
        };

        $isSafety = ($metrics['MSI'] ?? 'X') === 'S' || ($metrics['MSA'] ?? 'X') === 'S';

        $eq4 = match (true) {
            $isSafety => 0,
            $isHigh('SC') || $isHigh('SI') || $isHigh('SA') => 1,
            default => 2,
        };

        $eq5 = match ($resolved['E']) {
            'A' => 0,
            'P' => 1,
            default => 2,
        };

        $eq6 = ($isHigh('CR') && $isHigh('VC')) || ($isHigh('IR') && $isHigh('VI')) || ($isHigh('AR') && $isHigh('VA')) ? 0 : 1;

        return "{$eq1}{$eq2}{$eq3}{$eq4}{$eq5}{$eq6}";
    }

    /**
     * The class's score, less the mean share of the distance to the next lower
     * class that the vector has already travelled away from the most severe
     * vector of its own class.
     *
     * @param  array<string, string>  $resolved
     */
    private static function interpolate(array $resolved, string $macroVector): float
    {
        $value = self::LOOKUP[$macroVector];
        [$eq1, $eq2, $eq3, $eq4, $eq5, $eq6] = array_map(intval(...), str_split($macroVector));

        $distances = self::severityDistances($resolved, $macroVector, $eq3, $eq6);
        $step = 0.1;

        $classes = [
            ['lower' => self::lowerScore($macroVector, 0, $eq1), 'distance' => $distances['AV'] + $distances['PR'] + $distances['UI'], 'depth' => self::MAX_SEVERITY['eq1'][$eq1] * $step],
            ['lower' => self::lowerScore($macroVector, 1, $eq2), 'distance' => $distances['AC'] + $distances['AT'], 'depth' => self::MAX_SEVERITY['eq2'][$eq2] * $step],
            ['lower' => self::lowerEq3Eq6Score($macroVector, $eq3, $eq6), 'distance' => $distances['VC'] + $distances['VI'] + $distances['VA'] + $distances['CR'] + $distances['IR'] + $distances['AR'], 'depth' => self::MAX_SEVERITY['eq3eq6'][$eq3][$eq6] * $step],
            ['lower' => self::lowerScore($macroVector, 3, $eq4), 'distance' => $distances['SC'] + $distances['SI'] + $distances['SA'], 'depth' => self::MAX_SEVERITY['eq4'][$eq4] * $step],
            // the exploit maturity class never moves the score within itself
            ['lower' => self::lowerScore($macroVector, 4, $eq5), 'distance' => 0.0, 'depth' => 0.0],
        ];

        $travelled = 0.0;
        $existingLower = 0;

        foreach ($classes as $class) {
            if ($class['lower'] === null) {
                continue;
            }

            $existingLower++;
            $travelled += $class['depth'] > 0.0
                ? ($value - $class['lower']) * ($class['distance'] / $class['depth'])
                : 0.0;
        }

        $score = $existingLower === 0 ? $value : $value - ($travelled / $existingLower);

        return self::roundToTenth(max(0.0, min(10.0, $score)));
    }

    /**
     * Round to one decimal place, half up, immune to float noise. The tenths the
     * interpolation lands on are exact in decimal but not in binary: a vector
     * worth 8.55 computes as 8.549999999999999, which a plain round would report
     * as 8.5. Clearing the noise first keeps such a vector on the published
     * score, as the sources that publish v4.0 scores do.
     */
    private static function roundToTenth(float $value): float
    {
        return round(round($value * 10, 6)) / 10;
    }

    /**
     * How much less severe the vector is than the most severe vector of its own
     * class, metric by metric. Several vectors can be the most severe one; the
     * first that is at least as severe as this vector in every metric is used.
     *
     * @param  array<string, string>  $resolved
     * @return array<string, float>
     */
    private static function severityDistances(array $resolved, string $macroVector, int $eq3, int $eq6): array
    {
        $metrics = ['AV', 'PR', 'UI', 'AC', 'AT', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA', 'CR', 'IR', 'AR'];
        $distances = [];

        foreach (self::mostSevereVectors($macroVector, $eq3, $eq6) as $candidate) {
            $distances = [];

            foreach ($metrics as $metric) {
                $distances[$metric] = self::LEVELS[$metric][$resolved[$metric]] - self::LEVELS[$metric][$candidate[$metric]];
            }

            if (min($distances) >= 0.0) {
                break;
            }
        }

        return $distances;
    }

    /**
     * Every combination of the most severe vectors of the five classes, read as
     * metric maps.
     *
     * @return list<array<string, string>>
     */
    private static function mostSevereVectors(string $macroVector, int $eq3, int $eq6): array
    {
        $vectors = [''];

        foreach ([
            self::MAX_COMPOSED['eq1'][(int) $macroVector[0]],
            self::MAX_COMPOSED['eq2'][(int) $macroVector[1]],
            self::MAX_COMPOSED['eq3'][$eq3][$eq6],
            self::MAX_COMPOSED['eq4'][(int) $macroVector[3]],
            self::MAX_COMPOSED['eq5'][(int) $macroVector[4]],
        ] as $parts) {
            $combined = [];

            foreach ($vectors as $vector) {
                foreach ($parts as $part) {
                    $combined[] = $vector.$part;
                }
            }

            $vectors = $combined;
        }

        return array_map(self::parse(...), $vectors);
    }

    /**
     * @return array<string, string>
     */
    private static function parse(string $vector): array
    {
        $metrics = [];

        foreach (explode('/', trim($vector, '/')) as $pair) {
            $kv = explode(':', $pair, 2);

            if (count($kv) === 2) {
                $metrics[$kv[0]] = $kv[1];
            }
        }

        return $metrics;
    }

    /**
     * The score of the class one step less severe in the given position, or null
     * when there is none.
     */
    private static function lowerScore(string $macroVector, int $position, int $level): ?float
    {
        $lower = $macroVector;
        $lower[$position] = (string) ($level + 1);

        return self::LOOKUP[$lower] ?? null;
    }

    /**
     * The vulnerable and subsequent system classes move together. From 00 there
     * are two ways down and the less steep one is taken.
     */
    private static function lowerEq3Eq6Score(string $macroVector, int $eq3, int $eq6): ?float
    {
        if ($eq3 === 0 && $eq6 === 0) {
            $scores = array_filter([self::lowerScore($macroVector, 5, $eq6), self::lowerScore($macroVector, 2, $eq3)], fn (?float $score): bool => $score !== null);

            return $scores === [] ? null : max($scores);
        }

        if ($eq3 === 1 && $eq6 === 0) {
            return self::lowerScore($macroVector, 5, $eq6);
        }

        if ($eq3 === 2 && $eq6 === 1) {
            $lower = $macroVector;
            $lower[2] = (string) ($eq3 + 1);
            $lower[5] = (string) ($eq6 + 1);

            return self::LOOKUP[$lower] ?? null;
        }

        return self::lowerScore($macroVector, 2, $eq3);
    }
}
