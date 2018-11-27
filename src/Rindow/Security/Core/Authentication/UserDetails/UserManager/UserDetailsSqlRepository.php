<?php
namespace Rindow\Security\Core\Authentication\UserDetails\UserManager;

use Rindow\Database\Dao\Repository\GenericSqlRepository;
use Rindow\Database\Dao\Exception;

class UserDetailsSqlRepository extends GenericSqlRepository
{
    protected $tableName = 'rindow_authusers';
    protected $authoritiesTableName = 'rindow_authorities';

    public function setTableName($tableName)
    {
        if($tableName==null)
            return;
        parent::setTableName($tableName);
    }

    public function setAuthoritiesTableName($authoritiesTableName)
    {
        if($authoritiesTableName==null)
            return;
        $this->authoritiesTableName = $authoritiesTableName;
    }

    public function demap($entity)
    {
        $entity = parent::demap($entity);
        if(!is_array($entity))
            throw new Exception\InvalidArgumentException('Must be array.');
            
        unset($entity['authorities']);
        return $entity;
    }

    public function map($data)
    {
        $data = parent::map($data);
        $cursor = $this->getTableOperations()->find($this->authoritiesTableName,array('userid'=>$data['id']));
        $data['authorities'] = array();
        foreach($cursor as $row) {
            $data['authorities'][] = $row['authority'];
        }
        return $data;
    }

    protected function postCreate($entity)
    {
        parent::postCreate($entity);
        $this->createCascadedField(
            $entity,'authorities',$this->authoritiesTableName,'userid','authority');
    }

    protected function postUpdate($entity)
    {
        parent::postUpdate($entity);
        $this->updateCascadedField(
            $entity,'authorities',$this->authoritiesTableName,'userid','authority');
    }

    protected function preDelete($filter)
    {
        parent::preDelete($filter);
        $this->deleteCascadedField($filter,$this->authoritiesTableName,'userid');
    }
}
