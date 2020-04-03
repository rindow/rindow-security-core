<?php
date_default_timezone_set('UTC');
include __DIR__.'/../vendor/autoload.php';
define('RINDOW_TEST_CACHE',     __DIR__.'/cache');

if(!file_exists(__DIR__.'/data'))
	mkdir(__DIR__.'/data');

if(!class_exists('PHPUnit\Framework\TestCase')) {
    include __DIR__.'/travis/patch55.php';
}
if(getenv('TRAVIS_SKIP_TEST')) {
    define('TRAVIS_SKIP_TEST', true);
}
