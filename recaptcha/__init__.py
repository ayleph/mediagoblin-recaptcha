# GNU MediaGoblin -- federated, autonomous media hosting
# Copyright (C) 2011, 2012 MediaGoblin contributors.  See AUTHORS.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import os
import logging
import wtforms

from mediagoblin.init import ImproperlyConfigured
from mediagoblin.plugins.recaptcha import forms as captcha_forms
from mediagoblin.plugins.recaptcha import tools as captcha_tools
from mediagoblin.tools.translate import lazy_pass_to_ugettext as _
from mediagoblin.tools import pluginapi
from werkzeug.test import create_environ
from werkzeug.wrappers import Request

_log = logging.getLogger(__name__)
PLUGIN_DIR = os.path.dirname(__file__)


def setup_plugin():
    _log.info('Setting up recaptcha...')

    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')
    if config:
        if config.get('RECAPTCHA_SITE_KEY') == 'domainsitekey':
            configuration_error = 'You must configure the recaptcha plugin site key.'
            raise ImproperlyConfigured(configuration_error)
        if config.get('RECAPTCHA_SECRET_KEY') == 'domainsecretkey':
            configuration_error = 'You must configure the recaptcha plugin secret key.'
            raise ImproperlyConfigured(configuration_error)

    pluginapi.register_template_path(os.path.join(PLUGIN_DIR, 'templates'))

    pluginapi.register_template_hooks(
        {'captcha_challenge': 'mediagoblin/plugins/recaptcha/captcha_challenge.html'})

    # Create dummy request object to find register_form.
    environ = create_environ('/foo', 'http://localhost:8080/')
    request = Request(environ)
    register_form = pluginapi.hook_handle("auth_get_registration_form", request)
    del request

    # Add plugin-specific fields to register_form class.
    register_form_class = register_form.__class__
    register_form_class.g_recaptcha_response = captcha_forms.RecaptchaHiddenField('reCAPTCHA', id='g-recaptcha-response', name='g-recaptcha-response')
    register_form_class.remote_address = wtforms.HiddenField('')

    _log.info('Done setting up recaptcha!')


def add_to_form_context(context):
    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')
    context['recaptcha_site_key'] = config.get('RECAPTCHA_SITE_KEY')
    return context


hooks = {
    'setup': setup_plugin,
    'auth_extra_validation': captcha_tools.extra_validation,
    ('mediagoblin.auth.register',
     'mediagoblin/auth/register.html'): add_to_form_context,
}
