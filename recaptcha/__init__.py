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
from pkg_resources import resource_filename
import os
import logging

from mediagoblin.plugins.recaptcha import forms as captcha_forms
from mediagoblin.tools import pluginapi
from mediagoblin.tools.staticdirect import PluginStatic
_log = logging.getLogger(__name__)


PLUGIN_DIR = os.path.dirname(__file__)


def setup_plugin():
    _log.info('Setting up recaptcha...')
    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')
    if config:
        if config.get('RECAPTCHA_USE_SSL') == True:
            _log.info('reCAPTCHA is configured to use SSL.')
        else:
            _log.info('reCAPTCHA is NOT configured to use SSL.')

        if config.get('RECAPTCHA_PUBLIC_KEY') == 'domainpublickey':
            _log.warn('reCAPTCHA public key was not specified.')
        if config.get('RECAPTCHA_PRIVATE_KEY') == 'domainprivatekey':
            _log.warn('reCAPTCHA private key was not specified.')

    pluginapi.register_template_path(os.path.join(PLUGIN_DIR, 'templates'))

    pluginapi.register_template_hooks(
        {'captcha_challenge': 'mediagoblin/plugins/recaptcha/captcha_challenge.html'})

    _log.info('Done setting up recaptcha!')


def get_registration_form(request):
    return captcha_forms.RegistrationForm(request.form)


def no_pass_redirect():
    return 'recaptcha'




def append_to_global_context(context):
    context['pass_auth'] = True
    return context


hooks = {
    'setup': setup_plugin,
    'auth_get_user': get_user,
    'auth_create_user': create_user,
    'auth_get_login_form': get_login_form,
    'auth_get_registration_form': get_registration_form,
    'auth_no_pass_redirect': no_pass_redirect,
    'auth_gen_password_hash': gen_password_hash,
    'auth_check_password': check_password,
    'auth_fake_login_attempt': auth_tools.fake_login_attempt,
    #'template_global_context': append_to_global_context,
    'static_setup': lambda: PluginStatic(
        'coreplugin_recaptcha',
        resource_filename('mediagoblin.plugins.recaptcha', 'static'))
}
