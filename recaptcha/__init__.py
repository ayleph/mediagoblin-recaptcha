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

from mediagoblin.plugins.recaptcha import forms as captcha_forms
from mediagoblin.plugins.recaptcha import tools as captcha_tools
from mediagoblin import messages
from mediagoblin.tools.translate import lazy_pass_to_ugettext as _
from mediagoblin.tools import pluginapi
from mediagoblin.tools import request as request
from werkzeug.wrappers import Request

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


def transform_registration_form_class(request):
    register_form = pluginapi.hook_handle("auth_get_registration_form", request)
    register_form_base = register_form.__class__
    register_form_base.g_recaptcha_response = captcha_forms.RecaptchaHiddenField('reCAPTCHA', id='g-recaptcha-response', name='g-recaptcha-response')
    register_form_base.remote_address = wtforms.HiddenField('')


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
    context['recaptcha_public_key'] = config.get('RECAPTCHA_PUBLIC_KEY')

    return context


hooks = {
    'setup': setup_plugin,
    'registration_form_transform': transform_registration_form,
    'registration_form_class_transform': transform_registration_form_class,
    'auth_extra_validation': captcha_tools.extra_validation,
    ('mediagoblin.auth.register',
     'mediagoblin/auth/register.html'): add_to_form_context,
}
