<?php
namespace Rindow\Security\Core\Authorization\Support;

use Rindow\Stdlib\Cache\CacheHandlerTemplate;
use Rindow\Security\Core\Authorization\Exception;

class RoleHierarchy
{
    protected $hierarchy = array();
    protected $rolesReachableMap = array();
    protected $cacheKey;
    protected $cachePath = '';
    protected $built = false;
    protected $recursionTracking=array();

    public function __construct(array $hierarchy=null,$cacheKey=null,$cachePath=null)
    {
        if($hierarchy)
            $this->setHierarchy($hierarchy);
        if($cacheKey)
            $this->setCacheKey($cacheKey);
        if($cachePath)
            $this->setCachePath($cachePath);
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

    public function setCacheKey($cacheKey)
    {
        $this->cacheKey = $cacheKey;
    }

    public function setCachePath($cachePath)
    {
        $this->cachePath = $cachePath;
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
        if($this->cacheKey==null) {
            return;
        }
        $cacheHandler = new CacheHandlerTemplate($this->cachePath.__CLASS__);
        $cache = $cacheHandler->getCache($this->cacheKey);
        $roleHierarchy = $this;
        $map = $cache->get(
            'map',
            array(),
            function ($cache,$componentName,&$value) use ($roleHierarchy) {
                foreach($roleHierarchy->getHierarchy() as $role => $parents) {
                    $roleHierarchy->resolvReachables($role);
                }
                $value = $roleHierarchy->getRolesReachableMap();
                return true;
            }
        );
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
