<?php
namespace RindowTest\Security\Core\Authentication\SecurityContextTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\Support\SecurityContext;
use Rindow\Security\Core\Authentication\Token\AbstractAuthenticationToken;
use Rindow\Stdlib\Dict;

class TestToken  extends AbstractAuthenticationToken
{
}

class TestDefaultToken  extends AbstractAuthenticationToken
{
}

class Test extends TestCase
{
	public function testNormal()
	{
		$strage = new Dict();
		$context = new SecurityContext($strage,'key');
		$testToken = new TestToken();
		$testDefaultToken = new TestDefaultToken();

		$this->assertNull($context->getAuthentication());

		$context->setDefaultAuthentication($testDefaultToken);
		$this->assertEquals($testDefaultToken,$context->getAuthentication());

		$context->setAuthentication($testToken);
		$this->assertEquals($testToken,$context->getAuthentication());

		$context->setAuthentication(null);
		$this->assertEquals($testDefaultToken,$context->getAuthentication());
	}

	public function testLifetimeInTime()
	{
		$strage = new Dict();
		$context = new SecurityContext($strage,'key');
		$context->setLifetime(10000);
		$testToken = new TestToken();
		$testDefaultToken = new TestDefaultToken();

		$this->assertNull($context->getAuthentication());

		$context->setDefaultAuthentication($testDefaultToken);
		$this->assertEquals($testDefaultToken,$context->getAuthentication());

		$context->setAuthentication($testToken);
		$this->assertEquals($testToken,$context->getAuthentication());

		$context->setAuthentication(null);
		$this->assertEquals($testDefaultToken,$context->getAuthentication());
	}

	public function testLifetimeTimeout()
	{
		$strage = new Dict();
		$context = new SecurityContext($strage,'key');
		$context->setLifetime(null);
		$testToken = new TestToken();
		$testDefaultToken = new TestDefaultToken();

		$this->assertNull($context->getAuthentication());

		$context->setDefaultAuthentication($testDefaultToken);
		$this->assertEquals($testDefaultToken,$context->getAuthentication());

		$context->setAuthentication($testToken);
		$this->assertEquals($testToken,$context->getAuthentication());
		$this->assertEquals($testToken,$context->getAuthentication());

		$context->setLifetime(1000);
		$this->assertEquals($testToken,$context->getAuthentication());
		$this->assertEquals($testToken,$context->getAuthentication());

		$context->setLifetime(-1000);
		$this->assertEquals($testDefaultToken,$context->getAuthentication());
		$this->assertEquals($testDefaultToken,$context->getAuthentication());

		$context->setLifetime(1000);
		$this->assertEquals($testDefaultToken,$context->getAuthentication());
		$this->assertEquals($testDefaultToken,$context->getAuthentication());
	}
}
