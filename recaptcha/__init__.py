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
import wtforms

from mediagoblin import mg_globals, messages
from mediagoblin.plugins.recaptcha import forms as captcha_forms
from mediagoblin.tools.translate import lazy_pass_to_ugettext as _
from mediagoblin.tools import pluginapi
from mediagoblin.tools.staticdirect import PluginStatic

from recaptcha.client import captcha

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
        {'head': 'mediagoblin/plugins/recaptcha/bits/recaptcha_extra_head.html',
         'captcha_challenge': 'mediagoblin/plugins/recaptcha/captcha_challenge.html'})

    _log.info('Done setting up recaptcha!')


def get_registration_form(request):
    return captcha_forms.RegistrationForm(request.form)


def extra_validation(register_form):
    extra_validation_passes = False

    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')

    if register_form.validate():
        recaptcha_challenge = register_form.recaptcha_challenge_field.data if 'recaptcha_challenge_field' in register_form else None
        recaptcha_response = register_form.recaptcha_response_field.data if 'recaptcha_response_field' in register_form else None
        remote_addr = register_form.recaptcha_remote_addr.data if 'recaptcha_remote_addr' in register_form else None

        _log.debug('response field is: %r', recaptcha_response)
        _log.debug('challenge field is: %r', recaptcha_challenge)
        response = captcha.submit(
            recaptcha_challenge,
            recaptcha_response,
            config.get('RECAPTCHA_PRIVATE_KEY'),
            #request.remote_addr,
            remote_addr,
            )

        #goblin = response.is_valid
        extra_validation_passes = response.is_valid
        if response.error_code:
            _log.debug('reCAPTCHA error: %r', response.error_code)

        if not extra_validation_passes:
            register_form.recaptcha_response_field.errors.append(
                _('Sorry, captcha was incorrect. Please try again.'))

    return extra_validation_passes


def no_pass_redirect():
    return 'recaptcha'


def add_to_form_context(context):
    recaptcha_protocol = ''
    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')
    if config['RECAPTCHA_USE_SSL']:
        recaptcha_protocol = 'https'
    else:
        recaptcha_protocol = 'http'
    _log.debug('Connecting to reCAPTCHA service via %r', recaptcha_protocol)

    context['captcha'] = True
    context['recaptcha_protocol'] = recaptcha_protocol
    context['recaptcha_public_key'] = config.get('RECAPTCHA_PUBLIC_KEY'),

    return context


hooks = {
    'setup': setup_plugin,
    'auth_extra_validation': extra_validation,
    'auth_get_registration_form': get_registration_form,
    #'auth_no_pass_redirect': no_pass_redirect,
    #'template_global_context': append_to_global_context,
    #'static_setup': lambda: PluginStatic(
    #    'coreplugin_recaptcha',
    #    resource_filename('mediagoblin.plugins.recaptcha', 'static'))
    ('mediagoblin.auth.register',
     'mediagoblin/auth/register.html'): add_to_form_context,
}
