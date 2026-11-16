<?php

declare(strict_types=1);
$lock = json_decode(file_get_contents(__DIR__.'/../composer.lock'), true, 512, JSON_THROW_ON_ERROR);
$approved = ['MIT', 'BSD-3-Clause', 'BSD-2-Clause', 'Apache-2.0', 'ISC', 'Unlicense', '0BSD'];
foreach (array_merge($lock['packages'], $lock['packages-dev']) as $package) {
    // Composer license arrays declare alternatives; e.g. Nette offers BSD-3-Clause.
    if (array_intersect($approved, $package['license'] ?? []) === []) {
        fwrite(STDERR, 'Dependency license requires review: '.$package['name']."\n");
        exit(1);
    }
}
echo "Locked dependencies have a reviewed permissive license option.\n";
