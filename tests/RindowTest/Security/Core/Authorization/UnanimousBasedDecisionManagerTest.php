<?php
namespace RindowTest\Security\Core\Authorization\UnanimousBasedDecisionManagerTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authorization\Vote\AuthenticatedVoter;
use Rindow\Security\Core\Authorization\Vote\RoleVoter;
use Rindow\Security\Core\Authorization\Vote\UnanimousBased;
use Rindow\Security\Core\Authorization\AccessDecisionVoter;
use Rindow\Security\Core\Authentication\Support\AuthenticationTrustResolver;
use Rindow\Security\Core\Authentication\Token\RememberMeAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\AnonymousAuthenticationToken;
use Rindow\Security\Core\Authentication\Token\UsernamePasswordAuthenticationToken;

class Test extends TestCase
{
	public function testAllowed()
	{
		$voters = array(
			new AuthenticatedVoter(new AuthenticationTrustResolver()),
			new RoleVoter(),
		);
		$decisionManager = new UnanimousBased($voters);
		$authentication = new RememberMeAuthenticationToken('key','test',array('ROLE_USER'));

		$attributes = array('ROLE_USER',AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED);
		$object = null;
		$decisionManager->decide($authentication,$object,$attributes);
		$this->assertTrue(true);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\AccessDeniedException
     * @expectedExceptionMessage Access is denied.
     */
	public function testDenide1()
	{
		$voters = array(
			new AuthenticatedVoter(new AuthenticationTrustResolver()),
			new RoleVoter(),
		);
		$decisionManager = new UnanimousBased($voters);
		$authentication = new RememberMeAuthenticationToken('key','test',array('ROLE_USER'));

		$attributes = array('ROLE_USER',AuthenticatedVoter::IS_AUTHENTICATED_FULLY);
		$object = null;
		$decisionManager->decide($authentication,$object,$attributes);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\AccessDeniedException
     * @expectedExceptionMessage Access is denied.
     */
	public function testDenide2()
	{
		$voters = array(
			new AuthenticatedVoter(new AuthenticationTrustResolver()),
			new RoleVoter(),
		);
		$decisionManager = new UnanimousBased($voters);
		$authentication = new RememberMeAuthenticationToken('key','test',array('ROLE_USER'));

		$attributes = array('ROLE_OTHER',AuthenticatedVoter::IS_AUTHENTICATED_REMEMBERED);
		$object = null;
		$decisionManager->decide($authentication,$object,$attributes);
	}

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\AccessDeniedException
     * @expectedExceptionMessage Access is denied.
     */
	public function testAllAbstain()
	{
		$voters = array(
			new AuthenticatedVoter(new AuthenticationTrustResolver()),
			new RoleVoter(),
		);
		$decisionManager = new UnanimousBased($voters);
		$authentication = new RememberMeAuthenticationToken('key','test',array('ROLE_USER'));

		$attributes = array();
		$object = null;
		$decisionManager->decide($authentication,$object,$attributes);
	}
}
