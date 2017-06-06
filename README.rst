=====================
mediagoblin-recaptcha
=====================

This plugin enables reCAPTCHA support for GNU MediaGoblin. To use 
reCAPTCHA, you must have a (free) Google account with reCAPTCHA enabled 
for your MediaGoblin domain. This plugin does not provide 
authentication; it simply adds a reCAPTCHA field to the registration 
form provided by the configured authentication plugin.

Create a reCAPTCHA account
==========================

Go to reCAPTCHA_ and click ``Get reCAPTCHA``. Sign in with your Google 
account and add the domain for which you wish to use the reCAPTCHA 
service. You will need the site key and secret key for that domain to 
configure the recaptcha plugin.

Install the reCAPTCHA plugin
============================

1. Download the ``mediagoblin-recaptcha`` source. Copy the 
   ``recaptcha`` directory into the MediaGoblin plugins directory.

   ::

     $ git clone https://github.com/ayleph/mediagoblin-recaptcha.git
     $ cp -r mediagoblin-recaptcha/recaptcha /path/to/mediagoblin/mediagoblin/plugins/
    
2. Install the ``recaptcha-client`` python package, which is a 
   prerequisite for mediagoblin-recaptcha.

   ::

     $ pip install recaptcha-client

Configure the reCAPTCHA plugin
==============================

1. Ensure that an authentication plugin is enabled in your mediagoblin 
   configuration file. For example, to use the **basic_auth** plugin, 
   make sure the line below exists in your config file.

   ::

     [[mediagoblin.plugins.basic_auth]]

2. Enable the mediagoblin-recaptcha plugin by adding the following line 
   to the ``[plugins]`` section of your mediagoblin configuration file.

   ::

     [[mediagoblin.plugins.recaptcha]]

3. Enter your site and secret reCAPTCHA domain keys to your 
   mediagoblin configuration file under the recaptcha plugin.

::

    [[mediagoblin.plugins.recaptcha]]
    RECAPTCHA_SITE_KEY = 'domainsitekey'
    RECAPTCHA_SECRET_KEY = 'domainsecretkey'

4. Restart the MediaGoblin instance for the configuration file changes 
   to be effective.

.. external links

.. _reCAPTCHA: https://www.google.com/recaptcha/intro/index.html
