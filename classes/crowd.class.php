<?php

/**
 * Atlassian CROWD authentication backend
 *
 * @license   GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author    Jan Schumann <js@schumann-it.com>
 */
class auth_crowd extends auth_basic
{
	/**
	 * Wether we are in debug mode
	 *
	 * @var bool
	 */
	var $debug = true;

	/**
	 * The following options have to be set under $conf['auth']['crowd']:
	 *
	 * crowd_pear_lib_path => Path to PEAR Crowd Service File (e.g. /usr/share/php/Services/Atlassian/Crowd.php)
	 * app_name			   => The crowd app name
	 * app_credential      => The Password configureds in crowd
	 * service_url         => The crowd server wsdl url (usually 'http://<host>:8095/crowd/services/SecurityServer?wsdl'
	 *
	 * @var array
	 */
	var $cnf;

	/**
	 * The service instamce
	 *
	 * @link http://pear.php.net/package/Services_Atlassian_Crowd
	 *
	 * @var Services_Atlassian_Crowd
	 */
	var $crowd;

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
	 */
	function auth_crowd($config, $debug = false)
	{
		$this->debug = $debug;

		try
		{
			$this->crowd = new Services_Atlassian_Crowd(array(
				'app_name' => $config['app_name'],
				'app_credential' => $config['app_credential'],
				'service_url' => $config['service_url'])
			);
		}
		catch (Services_Atlassian_Crowd_Exception $e)
		{
			if ($this->debug) msg("AUTH err: Failed to create crowd service: " . $e->getMessage(), -1, __LINE__, __FILE__);
			$this->success = false;
			return;
		}

		try
		{
			$this->app_token = $this->crowd->authenticateApplication();
		}
		catch (Services_Atlassian_Crowd_Exception $e)
		{
			if ($this->debug) msg("AUTH err: Failed to authenticate app: " . $e->getMessage(), -1, __LINE__, __FILE__);
			$this->success = false;
			return;
		}
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
	function checkPass($user, $pass)
	{
		// reject empty password
		if (empty($pass)) return false;

		try
		{
			$this->user_tokens[$user] = $this->crowd->authenticatePrincipal($user, $pass, null, null);
		}
		catch (Services_Atlassian_Crowd_Exception $e)
		{
			msg("CROWD: could not authenticate user '" . $user . "': " . $e->getMessage(), -1, __LINE__, __FILE__);
			return false;
		}

		return true;
	}

	/**
	 * Return user info
	 *
	 * Returns info about the given user needs to contain
	 * at least these fields:
	 *
	 * name string  full name of the user
	 * mail string  email addres of the user
	 * grps array   list of groups the user is in
	 *
	 * This LDAP specific function returns the following
	 * addional fields:
	 *
	 * dn     string  distinguished name (DN)
	 * uid    string  Posix User ID
	 * inbind bool    for internal use - avoid loop in binding
	 *
	 * @author  Andreas Gohr <andi@splitbrain.org>
	 * @author  Trouble
	 * @author  Dan Allen <dan.j.allen@gmail.com>
	 * @author  <evaldas.auryla@pheur.org>
	 * @author  Stephane Chazelas <stephane.chazelas@emerson.com>
	 * @return  array containing user data or false
	 */
	function getUserData($user)
	{
		if (!$this->_validateUser($this->user_tokens[$user]))
		{
			msg("CROWD: User Token expired for: " . $user, -1, __LINE__, __FILE__);
			return false;
		}

		$info = $this->_getUserInfo($this->user_tokens[$user]);
		$info['grps'] = $this->_getGroups($user);

		return $info;
	}

	function _validateUser($token)
	{
		$valid = false;

		try {
			$valid = $this->crowd->isValidPrincipalToken($token);
		}
		catch (Services_Atlassian_Crowd_Exception $e)
		{
			msg("CROWD: Failed to validate User: " . $e->getMessage(), -1, __LINE__, __FILE__);
		}

		return $valid;
	}

	function _getUserInfo($token)
	{
		try {
			$principal = $this->crowd->findPrincipalByToken($token);
		}
		catch (Services_Atlassian_Crowd_Exception $e)
		{
			msg("CROWD: Failed to retrieve User: " . $e->getMessage(), -1, __LINE__, __FILE__);
			return false;
		}

		foreach ($principal->attributes->SOAPAttribute as $attribute)
		{
			$key = $attribute->name;
			if ($attribute->name === 'displayName') {
				$key = 'name';
			}
			$info[$key] = $attribute->values->string;
		}

		return $info;
	}

	function _getGroups($user)
	{
		try {
			 $groupMemberships = $this->crowd->findGroupMemberships($user);
		}
		catch (Services_Atlassian_Crowd_Exception $e)
		{
			msg("CROWD: Cannot retrieve groups: " . $e->getMessage(), -1, __LINE__, __FILE__);
			return false;
		}

		return reset($groupMemberships);
	}
}

//Setup VIM: ex: et ts=4 enc=utf-8 :
