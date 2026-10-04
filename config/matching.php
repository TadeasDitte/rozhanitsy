<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Language Runtimes
    |--------------------------------------------------------------------------
    |
    | CPE target_sw values that mark a package of a language runtime (a Ruby
    | gem, an npm module, ...) which may share its name with an unrelated native
    | product. Ranges bound to one of these are skipped by a check that names
    | neither a vendor nor an ecosystem. Platforms such as wordpress do not
    | belong here.
    |
    */

    'language_runtimes' => ['node.js', 'nodejs', 'ruby', 'php', 'python', 'perl', 'java', 'go', 'rust', '.net'],

    /*
    |--------------------------------------------------------------------------
    | Language Ecosystems
    |--------------------------------------------------------------------------
    |
    | OSV ecosystems whose package versions are upstream versions. A check that
    | names neither a vendor nor an ecosystem searches NVD plus these. Distro
    | ecosystems (Debian, Ubuntu, Alpine, ...) version their packages differently
    | and are only searched when the caller passes the exact ecosystem.
    |
    */

    'language_ecosystems' => ['npm', 'PyPI', 'Go', 'crates.io', 'RubyGems', 'Packagist', 'Maven', 'NuGet', 'Hex', 'Pub', 'CRAN', 'Hackage', 'SwiftURL'],

];
