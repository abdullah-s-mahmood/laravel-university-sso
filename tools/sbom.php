<?php

declare(strict_types=1);
$lock = json_decode(file_get_contents(__DIR__.'/../composer.lock'), true, 512, JSON_THROW_ON_ERROR);
$components = [];
foreach (array_merge($lock['packages'], $lock['packages-dev']) as $package) {
    [$group, $name] = explode('/', $package['name'], 2);
    $components[] = [
        'type' => 'library', 'group' => $group, 'name' => $name, 'version' => $package['version'],
        'purl' => 'pkg:composer/'.$package['name'].'@'.rawurlencode($package['version']),
        'licenses' => array_map(static fn (string $license): array => ['license' => ['name' => $license]], $package['license'] ?? []),
    ];
}
echo json_encode(['bomFormat' => 'CycloneDX', 'specVersion' => '1.6', 'version' => 1, 'components' => $components], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";
