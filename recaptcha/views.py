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
import logging

from itsdangerous import BadSignature

from mediagoblin import mg_globals, messages
from mediagoblin.auth.tools import register_user, check_login_simple
from mediagoblin.decorators import allow_registration, auth_enabled
from mediagoblin.plugins.recaptcha import forms as captcha_forms
from mediagoblin.tools import pluginapi
from mediagoblin.tools.response import redirect, render_to_response, render_404
from mediagoblin.tools.translate import pass_to_ugettext as _

from recaptcha.client import captcha

_log = logging.getLogger(__name__)


@allow_registration
@auth_enabled
def register(request):
    register_form = captcha_forms.RegistrationForm(request.form)
    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')

    recaptcha_protocol = ''
    if config['RECAPTCHA_USE_SSL']:
        recaptcha_protocol = 'https'
    else:
        recaptcha_protocol = 'http'
    _log.debug("Connecting to reCAPTCHA service via %r", recaptcha_protocol)

    if register_form.validate():
        recaptcha_challenge = request.form['recaptcha_challenge_field']
        recaptcha_response = request.form['recaptcha_response_field']
        _log.debug("response field is: %r", recaptcha_response)
        _log.debug("challenge field is: %r", recaptcha_challenge)
        response = captcha.submit(
            recaptcha_challenge,
            recaptcha_response,
            config.get('RECAPTCHA_PRIVATE_KEY'),
            request.remote_addr,
            )

        goblin = response.is_valid
        if response.error_code:
            _log.debug("reCAPTCHA error: %r", response.error_code)

        if goblin:
            user = register_user(request, register_form)

            if user:
                # redirect the user to their homepage... there will be a
                # message waiting for them to verify their email
                return redirect(
                    request, 'mediagoblin.user_pages.user_home',
                    user=user.username)

        else:
            messages.add_message(
                request,
                messages.WARNING,
                _('Sorry, captcha was incorrect. Please try again.'))

    return render_to_response(
        request,
        'mediagoblin/plugins/recaptcha/register.html',
        {'register_form': register_form,
         'post_url': request.urlgen('mediagoblin.plugins.recaptcha.register'),
         'recaptcha_public_key': config.get('RECAPTCHA_PUBLIC_KEY'),
         'recaptcha_protocol' : recaptcha_protocol})
