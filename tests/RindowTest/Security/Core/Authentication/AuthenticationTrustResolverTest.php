<?php
namespace RindowTest\Security\Core\Authentication\AuthenticationTrustResolverTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\AbstractAuthenticationToken;
use Rindow\Security\Core\Authentication\Support\AuthenticationTrustResolver;

class TestToken extends AbstractAuthenticationToken
{
}

class Test extends TestCase
{
	public function test()
	{
		$trustResolver = new AuthenticationTrustResolver();
		$anonymous = new AnonymousAuthenticationToken('key','ano',array('ROLE_ANONYMOUS'));
		$rememberMe = new RememberMeAuthenticationToken('key','saved',array('ROLE_USER'));

		$this->assertTrue($trustResolver->isAnonymous($anonymous));
		$this->assertFalse($trustResolver->isAnonymous($rememberMe));
		$this->assertFalse($trustResolver->isAnonymous(null));

		$this->assertFalse($trustResolver->isRememberMe($anonymous));
		$this->assertTrue($trustResolver->isRememberMe($rememberMe));
		$this->assertFalse($trustResolver->isRememberMe(null));

		$this->assertEquals(get_class($anonymous),$trustResolver->getAnonymousClass());
		$this->assertEquals(get_class($rememberMe),$trustResolver->getRememberMeClass());

		$testclass = new TestToken();

		$trustResolver->setAnonymousClass(get_class($testclass));
		$this->assertFalse($trustResolver->isAnonymous($anonymous));
		$this->assertFalse($trustResolver->isAnonymous($rememberMe));
		$this->assertTrue($trustResolver->isAnonymous($testclass));

		$this->assertFalse($trustResolver->isRememberMe($anonymous));
		$this->assertTrue($trustResolver->isRememberMe($rememberMe));
		$this->assertFalse($trustResolver->isRememberMe($testclass));


		$trustResolver->setAnonymousClass(get_class($anonymous));
		$trustResolver->setRememberMeClass(get_class($testclass));
		$this->assertTrue($trustResolver->isAnonymous($anonymous));
		$this->assertFalse($trustResolver->isAnonymous($rememberMe));
		$this->assertFalse($trustResolver->isAnonymous($testclass));

		$this->assertFalse($trustResolver->isRememberMe($anonymous));
		$this->assertFalse($trustResolver->isRememberMe($rememberMe));
		$this->assertTrue($trustResolver->isRememberMe($testclass));
	}
}
