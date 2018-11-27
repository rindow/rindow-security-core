<?php
namespace RindowTest\Security\Core\Authentication\InMemoryUserDetailsManagerTest;

use PHPUnit\Framework\TestCase;
use Rindow\Security\Core\Authentication\UserDetails\UserManager\InMemoryUserDetailsManager;
use Rindow\Security\Core\Authentication\UserDetails\User;
use Rindow\Stdlib\Dict;

class Test extends TestCase
{
    public function testLoadingDefaultSuccess()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
        $this->assertInstanceOf('Rindow\Security\Core\Authentication\UserDetails\User',$user);
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testLoadingDisabledSuccess()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
                'accountNonExpired'=>false,
                'accountNonLocked'=>false,
                'credentialsNonExpired'=>false,
                'enabled'=>false,
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertFalse($user->isAccountNonExpired());
        $this->assertFalse($user->isAccountNonLocked());
        $this->assertFalse($user->isCredentialsNonExpired());
        $this->assertFalse($user->isEnabled());
    }

    public function testAccountNonExpired()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
                'accountNonExpired'=>false
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertFalse($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testAccountNonLocked()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
                'accountNonLocked'=>false,
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertFalse($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testCredentialsNonExpired()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
                'credentialsNonExpired'=>false,
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertFalse($user->isCredentialsNonExpired());
        $this->assertTrue($user->isEnabled());
    }

    public function testDisabled()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
                'enabled'=>false,
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());
        $this->assertTrue($user->isAccountNonExpired());
        $this->assertTrue($user->isAccountNonLocked());
        $this->assertTrue($user->isCredentialsNonExpired());
        $this->assertFalse($user->isEnabled());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\UsernameNotFoundException
     * @expectedExceptionMessage foo
     */
    public function testUsernameNotFoundException()
    {
        $users = array(
            'aa' => array('password'=>'aaPass'),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
    }

    public function testUpdateSuccess()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());

        $user = new User('foo','boopass',array('ROLE_USER'));
        $manager->updateUser($user);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('boopass',$user->getPassword());
        $this->assertEquals(array('ROLE_USER'),$user->getAuthorities());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage unknown username:boo
     */
    public function testUpdateFailed()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);
        $user = $manager->loadUserByUsername('foo');
        $this->assertEquals('foo',$user->getUsername());
        $this->assertEquals('fooPass',$user->getPassword());
        $this->assertEquals(array('ROLE_ADMIN'),$user->getAuthorities());

        $user = new User('boo','boopass',array('ROLE_USER'));
        $manager->updateUser($user);
    }

    public function testCreateSuccess()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);

        $this->assertFalse($manager->userExists('boo'));
        $user = new User('boo','boopass',array('ROLE_USER'));
        $manager->createUser($user);
        $this->assertTrue($manager->userExists('boo'));

        $user = $manager->loadUserByUsername('boo');
        $this->assertEquals('boo',$user->getUsername());
        $this->assertEquals('boopass',$user->getPassword());
        $this->assertEquals(array('ROLE_USER'),$user->getAuthorities());
    }

    /**
     * @expectedException        Rindow\Security\Core\Authentication\Exception\InvalidArgumentException
     * @expectedExceptionMessage duplicate username:boo
     */
    public function testCreateFailed()
    {
        $users = array(
            'boo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);

        $user = new User('boo','boopass',array('ROLE_USER'));
        $manager->createUser($user);
    }

    public function testDeleteSuccess()
    {
        $users = array(
            'foo' => array(
                'id' => 1,
                'password'=>'fooPass',
                'roles'=>array('ADMIN'),
            ),
        );
        $manager = new InMemoryUserDetailsManager($users);

        $this->assertTrue($manager->userExists('foo'));
        $manager->deleteUser('foo');
        $this->assertFalse($manager->userExists('foo'));

        $this->assertFalse($manager->userExists('boo'));
        $manager->deleteUser('boo');
        $this->assertFalse($manager->userExists('boo'));
    }
}