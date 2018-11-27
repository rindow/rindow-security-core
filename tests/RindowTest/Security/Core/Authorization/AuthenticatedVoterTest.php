<?php
namespace RindowTest\Security\Core\Authorization\AuthenticatedVoterTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authorization\Vote\AuthenticatedVoter;
use Interop\Lenient\Security\Authorization\AccessDecisionVoter;
use Rindow\Security\Core\Authentication\Support\AuthenticationTrustResolver;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;

class Test extends TestCase
{
	public function testAnonymous()
	{
		$voter = new AuthenticatedVoter(new AuthenticationTrustResolver());
		$authentication = new AnonymousAuthenticationToken('key','test',array('ROLE_ANONYMOUS'));

		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_DENIED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_DENIED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY)));

		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY,AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED,AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_DENIED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY,AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED)));
	}

	public function testRememberMe()
	{
		$voter = new AuthenticatedVoter(new AuthenticationTrustResolver());
		$authentication = new RememberMeAuthenticationToken('key','test',array('ROLE_USER'));

		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_DENIED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY)));

		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY,AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED,AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY,AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED)));
	}

	public function testFullAuthenticated()
	{
		$voter = new AuthenticatedVoter(new AuthenticationTrustResolver());
		$authentication = new UsernamePasswordAuthenticationToken('user','pass',array('ROLE_USER'));

		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY)));

		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY,AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED,AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY)));
		$this->assertEquals(AccessDecisionVoter::ACCESS_GRANTED,
			$voter->vote($authentication, $object=null, array(AuthenticatedVoter::IS_AUTHENTICATED_FULLY,AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED)));
	}

	public function testSupports()
	{
		$voter = new AuthenticatedVoter();
		$this->assertTrue($voter->supports(AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED));
		$this->assertTrue($voter->supports(AuthenticatedVoter::IS_AUTHENTICATED_ANONYMOUSLY));
		$this->assertTrue($voter->supports(AuthenticatedVoter::IS_AUTHENTICATED_FULLY));
		$this->assertFalse($voter->supports('OTHER_AUTHORITY'));
		$this->assertFalse($voter->supports(null));
		$this->assertFalse($voter->supports(''));
	}
}
