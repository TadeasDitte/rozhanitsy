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

    /*
    |--------------------------------------------------------------------------
    | Vendor Aliases
    |--------------------------------------------------------------------------
    |
    | Groups of vendor names NVD and the CNAs use interchangeably for the same
    | products (WooCommerce is filed under both automattic and woocommerce). A
    | check naming one vendor of a group matches ranges of every vendor in it.
    |
    */

    'vendor_aliases' => [
        ['automattic', 'woocommerce'],
        ['tms-outsource', 'wpdatatables'],
        ['gutenberg_project', 'wordpress'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Backporting Products
    |--------------------------------------------------------------------------
    |
    | vendor:product pairs that ship security fixes on older release branches
    | too. A CNA range such as "< 7.1.2" with no lower bound also covers the
    | patched branch releases (7.0.7, 6.9.10, ...) of these, so when NVD has not
    | analysed the record yet, such a range is stored as low confidence.
    |
    */

    'backporting_products' => ['wordpress:wordpress'],

    /*
    |--------------------------------------------------------------------------
    | ADP Sources
    |--------------------------------------------------------------------------
    |
    | Organization ids of ADP containers (organizations other than the CNA that
    | add data to a CVE record, such as CISA's vulnrichment). Their affected
    | entries are guesses made after the fact and have mistakes such as module
    | CVEs filed under the platform, so their ranges are stored as low confidence.
    |
    */

    'adp_sources' => ['134c704f-9b21-4f2e-91b3-4a467353bcc0'],

];
