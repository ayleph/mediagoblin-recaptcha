=====================
mediagoblin-recaptcha
=====================

This plugin enables reCAPTCHA support for GNU MediaGoblin. To use 
reCAPTCHA, you must have a (free) Google account with reCAPTCHA enabled 
for your MediaGoblin domain. This plugin is currently incompatible with 
the ``basic_auth`` plugin.

Create a reCAPTCHA account
==========================

Go to reCAPTCHA_ and click ``Get reCAPTCHA``. Sign in with your Google 
account and add the domain for which you wish to use the reCAPTCHA 
service. You will need the public and private keys for that domain to 
configure the recaptcha plugin.

Set up the recaptcha plugin
===========================

1. Download the ``mediagoblin-recaptcha`` source and copy the 
   ``recaptcha`` directory into the MediaGoblin plugins directory.

   ::

     $ git clone https://github.com/ayleph/mediagoblin-recaptcha.git
     $ cp -r mediagoblin-recaptcha/recaptcha /path/to/mediagoblin/mediagoblin/plugins/
    
2. Install the ``recaptcha-client`` python package, which is a 
   prerequisite for mediagoblin-recaptcha.

   ::

     $ pip install recaptcha-client

3. Enable the mediagoblin-recaptcha plugin by adding the following line 
   to the ``[plugins]`` section of your mediagoblin configuration file.

   ::

     [[mediagoblin.plugins.recaptcha]]

4. Disable the basic authentication plugin in your mediagoblin 
   configuration file. Change

   ::

     [[mediagoblin.plugins.basic_auth]]

   to

   ::

     [[-mediagoblin.plugins.basic_auth]]

5. Restart the MediaGoblin instance for the configuration file changes 
   to be effective.

Configure the recaptcha plugin
==============================

You must provide the public and private keys for your reCAPTCHA domain 
and specify whether or not to use SSL. If your site is served over 
https, set ``RECAPTCHA_USE_SSL = true``. If your site is served over 
http, set ``RECAPTCHA_USE_SSL = false``. Failure to correctly set 
``RECAPTCHA_USE_SSL`` will prevent the reCAPTCHA widget from displaying 
properly. Add the following entries to your mediagoblin configuration 
file under the recaptcha plugin.

::

    [[mediagoblin.plugins.recaptcha]]
    RECAPTCHA_PUBLIC_KEY = 'domainpublickey'
    RECAPTCHA_PRIVATE_KEY = 'domainprivatekey'
    RECAPTCHA_USE_SSL = true/false

.. external links

.. _reCAPTCHA: https://www.google.com/recaptcha/intro/index.html
