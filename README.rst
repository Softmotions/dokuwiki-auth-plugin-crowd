An Athentication plugin for Dokuwiki
====================================

Installation
------------

Look for the latest Tag https://github.com/janschumann/dokuwiki-auth-plugin-crowd/tags, copy the ZIP-File download-link and paste it to the plugin manager.


Config
------

Example:

::

    $conf['authtype']  = 'crowd';
    $conf['superuser'] = '@wiki-admins';
    $conf['manager']   = '@wiki-managers';
    $conf['plugin']['crowd']['app_name']       = 'wiki';
    $conf['plugin']['crowd']['app_credential'] = 'pass';
    $conf['plugin']['crowd']['service_url']    = 'http://crowd.example.com:8095/crowd/services/SecurityServer?wsdl';

