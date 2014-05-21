=====================
mediagoblin-recaptcha
=====================

This plugin enables reCAPTCHA support for Gnu MediaGoblin. To use reCAPTCHA, you must have a (free) Google account with reCAPTCHA enabled for your domain(s).

Create a reCAPTCHA account
==========================

Go to `https://www.google.com/recaptcha/intro/index.html`_ and click ``Get reCAPTCHA``. Sign in with your Google account and add the domain(s) for which you which to use the reCAPTCHA service. You will need the public and private keys for that domain to configure the recaptcha plugin.

Set up the recaptcha plugin
===========================

1. Install the ``recaptcha-client`` python package.
    pip install recaptcha-client
    
2. Add the following to your mediagoblin_local.ini file in the ``[plugins]`` section::
    [[mediagoblin.plugins.recaptcha]]

Configure the recaptcha plugin
==============================

You must provide the public and private keys for your reCAPTCHA domain. Add the following entries to your mediagoblin_local.ini file under the recaptcha plugin::

    [[mediagoblin.plugins.recaptcha]]
    RECAPTCHA_PUBLIC_KEY = 'domainpublickey'
    RECAPTCHA_PRIVATE_KEY = 'domainprivatekey'
