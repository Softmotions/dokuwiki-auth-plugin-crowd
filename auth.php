<?php

// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();

//define('CUSTOM_PEAR', '/path/to/custom/pear/installatin');

if (defined('CUSTOM_PEAR'))  ini_set('include_path', ini_get('include_path').PATH_SEPARATOR.CUSTOM_PEAR);

foreach(explode(PATH_SEPARATOR, ini_get('include_path')) as $dir) {
	if (file_exists($dir."/Services/Atlassian/Crowd.php")) {
		require_once('Services/Atlassian/Crowd.php');
		break;
	}
}

//require_once DOKU_INC.'inc/auth/basic.class.php';
require_once dirname(__FILE__) . '/classes/crowd.class.php';

class auth_plugin_crowd extends DokuWiki_Auth_Plugin
{
	var $auth;

	function auth_plugin_crowd() {
		global $conf;

		if (!class_exists('Services_Atlassian_Crowd')) {
			msg('Plugin err: Pear library "Services_Atlassian_Crowd" is required by plugin "' . $this->getPluginName() . '"', -1, __LINE__, __FILE__);
		}

		$this->debug = $conf['debug'];
		$this->loadConfig();
	}

	function getAuth() {
		if (!isset($this->auth)) {
			$this->auth = new auth_crowd($this->conf, $this->debug);
		}

		return $this->auth;
	}
}
