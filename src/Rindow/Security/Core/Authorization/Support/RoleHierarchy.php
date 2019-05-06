<?php
namespace Rindow\Security\Core\Authorization\Support;

use Rindow\Stdlib\Cache\ConfigCache\ConfigCacheFactory;
use Rindow\Security\Core\Authorization\Exception;

class RoleHierarchy
{
    protected $hierarchy = array();
    protected $rolesReachableMap = array();
    protected $cache;
    protected $cacheTtl;
    protected $cacheKey='map';
    protected $built = false;
    protected $recursionTracking=array();

    public function __construct(array $hierarchy=null,/*SimpleCache*/ $cache=null,$cacheTtl=null,$cacheKey=null)
    {
        if($hierarchy)
            $this->setHierarchy($hierarchy);
        if($cache)
            $this->setCache($cache);
        if($cacheTtl)
            $this->setCacheTtl($cacheTtl);
        if($cacheKey)
            $this->setCacheKey($cacheKey);
    }

    /**
     * @return array $hierarchy Role Hierarchy Representation
     */
    public function setHierarchy(array $hierarchy=null)
    {
        if($hierarchy==null)
            return;
        $this->hierarchy = $hierarchy;
    }

    public function getHierarchy()
    {
        return $this->hierarchy;
    }

    public function setCache(/*SimpleCache*/ $cache)
    {
        $this->cache = $cache;
    }

    public function setCacheKey($cacheKey)
    {
        $this->cacheKey = $cacheKey;
    }

    public function setCacheTtl($cacheTtl)
    {
        $this->cacheTtl = $cacheTtl;
    }

    protected function getCache()
    {
        return $this->cache;
    }


    /**
     * @return array Roles
     */
    public function getReachableGrantedAuthorities(array $authorities=null)
    {
        if(empty($authorities))
            return array();
        $this->buildRolesReachableMap();

        $reachableRoles = array();
        foreach($authorities as $authority) {
            $reachableRoles = array_merge($reachableRoles,$this->resolvReachables($authority));
        }

        return array_values(array_unique($reachableRoles));
    }

    protected function buildRolesReachableMap()
    {
        if($this->built)
            return;
        if(!$this->cache)
            return;
        $cache = $this->getCache();
        $map = $cache->get(__CLASS__.'/'.$this->cacheKey);
        if($map===null) {
            foreach($this->getHierarchy() as $role => $parents) {
                $this->resolvReachables($role);
            }
            $map = $this->getRolesReachableMap();
            $cache->set(__CLASS__.'/'.$this->cacheKey,$map,$this->cacheTtl);
        }
        $this->rolesReachableMap = $map;
        $this->built = true;
    }

    public function getRolesReachableMap()
    {
        return $this->rolesReachableMap;
    }

    public function resolvReachables($role)
    {
        if(array_key_exists($role, $this->rolesReachableMap))
            return $this->rolesReachableMap[$role];
        if(!array_key_exists($role, $this->hierarchy))
            return array($role);

        if(!array_key_exists($role, $this->recursionTracking)) {
            $this->recursionTracking[$role] = true;
        } else {
            throw new Exception\DomainException('a recursion hierarchy is detected in "'.$role.'"');
        }

        $parents = $this->hierarchy[$role];
        $reachables = array($role);
        foreach ($parents as $parent) {
            $reachables = array_merge($reachables,$this->resolvReachables($parent));
        }
        $reachables = array_unique($reachables);
        $this->rolesReachableMap[$role] = $reachables;
        unset($this->recursionTracking[$role]);
        return $reachables;
    }
}
