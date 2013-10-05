<?php

namespace LdapUtils;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * Description of Group
 *
 * @author Администратор
 */
class UserUtils {

    /**
     * 
     * @param string полное имя пользователя $username alexey_baranov | alexey_baranov@tele-plus.office | corp\alexey_baranov
     * @return string короткое имя пользователя alexey_baranov
     */
    static function getShortUsername($username) {
        $result = preg_replace('/@.+/', "", $username);

        return $result;
    }

    /**
     * 
     * @param string $name Имя пользователя с доменом или без alexey_baranov | alexey_baranov@tele-plus.office
     * @param array $ldapOptions Опции для подключения к LDAP-серверу включая username и password
     * @throws \Exception Пользователь не найден
     * @return \Zend\Ldap\Node Пользователь
     */
    static function getUserByName($name, $ldapOptions) {
        $ldap = new \Zend\Ldap\Ldap($ldapOptions);
        $ldap->bind($ldapOptions["username"], $ldapOptions["password"]);

        $users = $ldap->search("(&(objectclass=person)(sAMAccountName=" . self::getShortUsername($name) . "))", $ldapOptions["baseDn"], \Zend\Ldap\Ldap::SEARCH_SCOPE_SUB);

        if (!$users->count()) {
            return new \Exception("Пользователь \"{$username}\" не найден");
        }

        $userAsArray = $users->getFirst();

//            $user = \Zend\Ldap\Node::fromLdap(\Zend\Ldap\Attribute::getAttribute($userAsArray, "distinguishedname", 0), $ldap);
        $result = \Zend\Ldap\Node::fromArray($userAsArray, true);
        $result->attachLdap($ldap);

        return $result;
    }

    /**
     * 
     * @param \Zend\Ldap\Node $node пользователь или группа
     * @param array $memberOf
     */
    static function collectNodeMemberOf(\Zend\Ldap\Node $node, &$memberOf) {
        foreach ($node->getAttribute("memberof") as $EACH_MEMBER_OF) {
            try {
                $eachMemberOf = \Zend\Ldap\Node::fromLdap($EACH_MEMBER_OF, $node->getLdap());
                $EACH_MEMBER_OF= bin2hex($eachMemberOf->getAttribute("objectguid", 0));
                
                if (!array_filter($memberOf, function($each) use ($eachMemberOf){
                    return $each->getAttribute("objectguid", 0) == $eachMemberOf->getAttribute("objectguid", 0);
                })){
                    $memberOf[] = $eachMemberOf;
                    self::collectNodeMemberOf($eachMemberOf, $memberOf);
                }
            }
            //возможен вариант, когда группа не входит в base_dn
            catch (\Zend\Ldap\Exception $ex) {
                \Logger::getLogger(get_class($this))->warn("Группа $EACH_MEMBER_OF не может быть загружена. Возможно она расположена за пределами BaseDn {$node->getLdap()->getBaseDn()}");
            }
        }
    }

    /**
     * Возвращает группы пользователей
     * 
     * @param \Zend\Ldap\Node $node
     * @return array
     */
    static function getNodeMemberOf(\Zend\Ldap\Node $node) {
        $result = array();

        self::collectNodeMemberOf($node, $result);

        return $result;
    }

    /**
     * ***["USER"=>"alexey_baranov@tele-plus.office", "GROUPs"=>[ , , ,] ]
     * 
     * @param string $USER Имя пользователя с доменом или без alexey_baranov | alexey_baranov@tele-plus.office
     * @param array $ldapOptions опции для подключения к LDAP-серверу включая username и password
     * @return array Группы пользователя
     */
    static function getUSERMemberOf($USER, $ldapOptions) {
        $ldap = new \Zend\Ldap\Ldap($ldapOptions);
        $ldap->bind($ldapOptions["username"], $ldapOptions["password"]);

        $users = $ldap->search("(&(objectclass=person)(sAMAccountName=" . self::getShortUsername($USER) . "))", $ldapOptions["baseDn"], \Zend\Ldap\Ldap::SEARCH_SCOPE_SUB);

        if (!$users->count()) {
            throw new \Exception("Пользователь \"{$USER}\" не найден");
        }

        $userAsArray = $users->getFirst();

//            $user = \Zend\Ldap\Node::fromLdap(\Zend\Ldap\Attribute::getAttribute($userAsArray, "distinguishedname", 0), $ldap);
        $user = \Zend\Ldap\Node::fromArray($userAsArray, true);
        $user->attachLdap($ldap);

        $result = self::getNodeMemberOf($user);

        return $result;
    }

    static function compareObjectGuids($value1, $value2){
        $value1= preg_replace('/[^\w\d]/', "", mb_strtolower($value1, "utf-8"));
        $value2= preg_replace('/[^\w\d]/', "", mb_strtolower($value2, "utf-8"));
        
        $value1Strange= preg_replace('/^(..)(..)(..)(..)(..)(..)(..)(..)/', "\\4\\3\\2\\1\\6\\5\\8\\7", $value1);
        
        return $value1==$value2 || $value1Strange== $value2;
    }
    /**
     * 
     * @param type $USER Имя пользователя
     * @param type $MEMBER_OF objectguid группы
     * @param type $ldapOptions массив опция для подключени к LDAP-серверу включая username и password
     * @return boolean
     */
    static function isUSERMemberOF($USER, $MEMBER_OF, $ldapOptions) {
        foreach (self::getUSERMemberOf($USER, $ldapOptions) as $eachMemberOf) {
            if (self::compareObjectGuids($MEMBER_OF, bin2hex($eachMemberOf->getAttribute("objectguid", 0)))) {
                return true;
            }
        }
        return false;
    }
}