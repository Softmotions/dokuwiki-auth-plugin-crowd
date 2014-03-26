<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

require_once('Services/Atlassian/Crowd.php');

// define crowd cookie
if (!defined('CROWD_TOKEN_COOKIE')) {
	define('CROWD_TOKEN_COOKIE', 'crowd.token_key');
}

global $conf;

/**
 * Atlassian Crowd authentication backend
 */
class auth_plugin_crowd extends DokuWiki_Auth_Plugin {
	
	/**
	 * The Crowd Application Token
	 *
	 * @var string
	 */
	var $app_token;
	
	
	/**
	 * An array of user tokens
	 *
	 * @var array
	 */
	var $user_tokens = array();
  
    /**
     * Constructor
     *
     * Carry out sanity checks to ensure the object is
     * able to operate. Set capabilities.
     *
     * @author  Christopher Smith <chris@jalakai.co.uk>
     */
    public function __construct() {
        parent::__construct();
        $this->cando['external'] = true;
        $this->cando['logout'] = true; 
    }
    
    /**
     * Do all authentication [ OPTIONAL ]
     *
     * Set $this->cando['external'] = true when implemented
     *
     * If this function is implemented it will be used to
     * authenticate a user - all other DokuWiki internals
     * will not be used for authenticating, thus
     * implementing the checkPass() function is not needed
     * anymore.
     *
     * The function can be used to authenticate against third
     * party cookies or Apache auth mechanisms and replaces
     * the auth_login() function
     *
     * The function will be called with or without a set
     * username. If the Username is given it was called
     * from the login form and the given credentials might
     * need to be checked. If no username was given it
     * the function needs to check if the user is logged in
     * by other means (cookie, environment).
     *
     * The function needs to set some globals needed by
     * DokuWiki like auth_login() does.
     *
     * @see     auth_login()
     * @author  Andreas Gohr <andi@splitbrain.org>
     *      
     * @param   string  $user    Username
     * @param   string  $pass    Cleartext Password
     * @param   bool    $sticky  Cookie should not expire
     * @return  bool             true on successful auth
     */
    public function trustExternal($user, $pass, $sticky = false) {
		//crowd.token_key cookie
		global $USERINFO, $ID;
		
		if (!empty($_SESSION[DOKU_COOKIE]['crowd']['info'])) {
            $USERINFO['name'] = $_SESSION[DOKU_COOKIE]['crowd']['info']['name'];
            $USERINFO['mail'] = $_SESSION[DOKU_COOKIE]['crowd']['info']['mail'];
            $USERINFO['grps'] = $_SESSION[DOKU_COOKIE]['crowd']['info']['grps'];
            $_SERVER['REMOTE_USER'] =  $_SESSION[DOKU_COOKIE]['crowd']['user'];
            return true;
		}

		$crowd = $this->_getCrowd();
		$token = NULL;
		if (empty($user)) {
			$token = $_COOKIE[CROWD_TOKEN_COOKIE];
		} else {
			if (!$this->checkPass($user, $pass)) {
				return false;
			}
			$token = $this->user_tokens[$user];
		}
		if (!isset($token)) {
			return false;
		}
		$info = $this->getUserData($user);
		if (!$info) {
			return false;
		}
		$USERINFO['name'] = $info['name'];
        $USERINFO['mail'] = $info['mail'];
        $USERINFO['grps'] = $info['grps'];
        
        $_SERVER['REMOTE_USER'] = $user;
        $_SESSION[DOKU_COOKIE]['crowd']['user'] = $user;
        $_SESSION[DOKU_COOKIE]['crowd']['pass'] = $pass;
        $_SESSION[DOKU_COOKIE]['crowd']['info'] = $USERINFO;
    }
    
     /**
     * Log off the current user [ OPTIONAL ]
     *
     * Is run in addition to the ususal logoff method. Should
     * only be needed when trustExternal is implemented.
     *
     * @see     auth_logoff()
     * @author  Andreas Gohr <andi@splitbrain.org>
     */
    public function logOff() {
		unset($_SESSION[DOKU_COOKIE]['crowd']);
		unset($_COOKIE[$CROWD_TOKEN_COOKIE]);
    }
    
    /**
	 * Check user+password
	 *
	 * Checks if the given user exists and the given
	 * plaintext password is correct by trying to bind
	 * to the LDAP server
	 *
	 * @author  Andreas Gohr <andi@splitbrain.org>
	 * @return  bool
	 */
	function checkPass($user, $pass){
		// reject empty password
		if (empty($pass)) return false;
		try {
			$this->user_tokens[$user] = $this->_getCrowd()->authenticatePrincipal($user, $pass, null, null);
		} catch (Services_Atlassian_Crowd_Exception $e) {
			$this->app_token = NULL;
			msg("CROWD: could not authenticate user '" . $user . "': " . $e->getMessage(), -1, __LINE__, __FILE__);
			return false;
		}
		return true;
	}
	
	public function getUserData($user)	{
		if (!isset($this->user_tokens[$user])) {
			return false;
		}
		if (!$this->_isValidToken($this->user_tokens[$user])) {
			$this->app_token = NULL;
			//msg("CROWD: User Token expired for: " . $user, -1, __LINE__, __FILE__);
			return false;
		}
		$info = $this->_getUserInfo($this->user_tokens[$user]);
		$info['grps'] = $this->_getGroups($user);
		return $info;
	}
    
    function _getCrowd() {
		if (isset($this->crowd) && isset($this->app_token)) {
			return $this->crowd;
		}
		if (!isset($this->crowd)) {
			try {
				$this->crowd = new Services_Atlassian_Crowd(array(
						'app_name' => $this->getConf('app_name'),
						'app_credential' => $this->getConf('app_credential'),
						'service_url' => $this->getConf('service_url')));		
			} catch (Services_Atlassian_Crowd_Exception $e) {
				msg("AUTH err: Failed to create crowd service: " . $e->getMessage(), -1, __LINE__, __FILE__);
				$this->success = false;
				return;
			}
		}	
		try	{
			$this->app_token = $this->crowd->authenticateApplication();
		} catch (Services_Atlassian_Crowd_Exception $e)	{
			msg("CROWD AUTH err: Failed to authenticate app: " . $e->getMessage(), -1, __LINE__, __FILE__);
			$this->success = false;
			return;
		}
	}
    
    function _isValidToken($token)	{
		$valid = false;
		try {
			$valid = $this->_getCrowd()->isValidPrincipalToken($token);
		} catch (Services_Atlassian_Crowd_Exception $e) {
			msg("CROWD: Failed to validate User: " . $e->getMessage(), -1, __LINE__, __FILE__);
		}
		return $valid;
	}
	
	function _getUserInfo($token){
		try {
			$principal = $this->_getCrowd()->findPrincipalByToken($token);
		} catch (Services_Atlassian_Crowd_Exception $e) {
			msg("CROWD: Failed to retrieve User: " . $e->getMessage(), -1, __LINE__, __FILE__);
			return false;
		}
		foreach ($principal->attributes->SOAPAttribute as $attribute) {
			$key = $attribute->name;
			if ($attribute->name === 'displayName') {
				$key = 'name';
			}
			$info[$key] = $attribute->values->string;
		}
		return $info;
	}

	function _getGroups($user) {
		try {
			 $groupMemberships = $this->_getCrowd()->findGroupMemberships($user);
		} catch (Services_Atlassian_Crowd_Exception $e) {
			$this->app_token = NULL;
			msg("CROWD: Cannot retrieve groups: " . $e->getMessage(), -1, __LINE__, __FILE__);
			return false;
		}
		return reset($groupMemberships);
	}
}

?>
