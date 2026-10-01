<?php

test('every class under app/ is declared in a file with exactly its name', function () {
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__, 2).'/app'));

    $mismatches = [];

    foreach ($files as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        if (preg_match('/^\s*(?:(?:final|abstract|readonly)\s+)*(?:class|interface|trait|enum)\s+(\w+)/m', file_get_contents($file->getPathname()), $match)
            && $match[1] !== $file->getBasename('.php')) {
            $mismatches[] = $file->getPathname().' declares '.$match[1];
        }
    }

    expect($mismatches)->toBe([]);
});
