<?php
namespace RindowTest\Security\Core\Authorization\RoleHierarchyTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authorization\Support\RoleHierarchy;
use Rindow\Stdlib\Cache\SimpleCache\ArrayCache;

class Test extends TestCase
{
    public function setUp()
    {
    }

    public function testGetReachable()
    {
        $hierarchy = new RoleHierarchy(array(
            'ROLE_ADMIN'     => array('ROLE_OPERATOR','ROLE_DEVELOPER'),
            'ROLE_OPERATOR'  => array('ROLE_USER'),
            'ROLE_DEVELOPER' => array('ROLE_USER'),
            'ROLE_USER'      => array('ROLE_ANONYMOUS'),
        ));

        $answer = array(
            'ROLE_ADMIN','ROLE_OPERATOR','ROLE_USER','ROLE_ANONYMOUS','ROLE_DEVELOPER',
        );
        $this->assertEquals($answer,$hierarchy->resolvReachables('ROLE_ADMIN'));

        $answer = array(
            'ROLE_USER'      => array('ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_OPERATOR'  => array('ROLE_OPERATOR','ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_DEVELOPER' => array('ROLE_DEVELOPER','ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_ADMIN'     => array('ROLE_ADMIN','ROLE_OPERATOR','ROLE_USER','ROLE_ANONYMOUS','ROLE_DEVELOPER'),
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());

        $answer = array(
            'ROLE_USER','ROLE_ANONYMOUS','ROLE_OPERATOR','ROLE_OTHER',
        );
        $this->assertEquals($answer,$hierarchy->getReachableGrantedAuthorities(array('ROLE_USER','ROLE_OPERATOR','ROLE_OTHER')));
    }

    /**
     * @expectedException        Rindow\Security\Core\Authorization\Exception\DomainException
     * @expectedExceptionMessage a recursion hierarchy is detected in "ROLE_ADMIN"
     */
    public function testRecursionhierarchy()
    {
        $hierarchy = new RoleHierarchy(array(
            'ROLE_ADMIN'     => array('ROLE_OPERATOR'),
            'ROLE_OPERATOR'  => array('ROLE_ADMIN'),
        ));
        $hierarchy->resolvReachables('ROLE_ADMIN');
    }

    public function testNoCache()
    {
        $hierarchy = new RoleHierarchy(array(
            'ROLE_ADMIN'     => array('ROLE_OPERATOR','ROLE_DEVELOPER'),
            'ROLE_OPERATOR'  => array('ROLE_USER'),
            'ROLE_DEVELOPER' => array('ROLE_USER'),
            'ROLE_USER'      => array('ROLE_ANONYMOUS'),
        ));

        $answer = array(
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());

        $answer = array(
            'ROLE_ANONYMOUS',
        );
        $this->assertEquals($answer,$hierarchy->resolvReachables('ROLE_ANONYMOUS'));

        $answer = array(
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());

        $answer = array(
            'ROLE_ANONYMOUS',
        );
        $this->assertEquals($answer,$hierarchy->getReachableGrantedAuthorities(array('ROLE_ANONYMOUS')));

        $answer = array(
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());

        // No cache

        $hierarchy = new RoleHierarchy(array(
            'ROLE_ADMIN'     => array('ROLE_OPERATOR','ROLE_DEVELOPER'),
            'ROLE_OPERATOR'  => array('ROLE_USER'),
            'ROLE_DEVELOPER' => array('ROLE_USER'),
            'ROLE_USER'      => array('ROLE_ANONYMOUS'),
        ));
        $answer = array(
            'ROLE_ANONYMOUS',
        );
        $this->assertEquals($answer,$hierarchy->getReachableGrantedAuthorities(array('ROLE_ANONYMOUS')));

        $answer = array(
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());

    }

    public function testCache()
    {
        $cache = new ArrayCache();
        $hierarchy = new RoleHierarchy(array(
            'ROLE_ADMIN'     => array('ROLE_OPERATOR','ROLE_DEVELOPER'),
            'ROLE_OPERATOR'  => array('ROLE_USER'),
            'ROLE_DEVELOPER' => array('ROLE_USER'),
            'ROLE_USER'      => array('ROLE_ANONYMOUS'),
        ), $cache);

        $answer = array(
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());

        $answer = array(
            'ROLE_ANONYMOUS',
        );
        $this->assertEquals($answer,$hierarchy->resolvReachables('ROLE_ANONYMOUS'));

        $answer = array(
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());

        $answer = array(
            'ROLE_ANONYMOUS',
        );
        $this->assertEquals($answer,$hierarchy->getReachableGrantedAuthorities(array('ROLE_ANONYMOUS')));

        $answer = array(
            'ROLE_USER'      => array('ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_OPERATOR'  => array('ROLE_OPERATOR','ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_DEVELOPER' => array('ROLE_DEVELOPER','ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_ADMIN'     => array('ROLE_ADMIN','ROLE_OPERATOR','ROLE_USER','ROLE_ANONYMOUS','ROLE_DEVELOPER'),
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());

        // Use cache

        $hierarchy = new RoleHierarchy(array(),$cache);

        $answer = array(
            'ROLE_ANONYMOUS',
        );
        $this->assertEquals($answer,$hierarchy->getReachableGrantedAuthorities(array('ROLE_ANONYMOUS')));

        $answer = array(
            'ROLE_USER'      => array('ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_OPERATOR'  => array('ROLE_OPERATOR','ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_DEVELOPER' => array('ROLE_DEVELOPER','ROLE_USER','ROLE_ANONYMOUS'),
            'ROLE_ADMIN'     => array('ROLE_ADMIN','ROLE_OPERATOR','ROLE_USER','ROLE_ANONYMOUS','ROLE_DEVELOPER'),
        );
        $this->assertEquals($answer,$hierarchy->getRolesReachableMap());
    }
}
