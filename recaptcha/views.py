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

from mediagoblin import mg_globals, messages
from mediagoblin.auth.tools import register_user, check_login_simple
from mediagoblin.db.models import User
from mediagoblin.decorators import allow_registration, auth_enabled
from mediagoblin.plugins.recaptcha import forms as auth_forms
from mediagoblin.tools import pluginapi
from mediagoblin.tools.translate import pass_to_ugettext as _
from mediagoblin.tools.response import redirect, render_to_response

from recaptcha.client import captcha

_log = logging.getLogger(__name__)


@auth_enabled
def login(request):
    """
    MediaGoblin login view.

    If you provide the POST with 'next', it'll redirect to that view.
    """
    #if 'pass_auth' not in request.template_env.globals:
    #    redirect_name = hook_handle('auth_no_pass_redirect')
    #    if redirect_name:
    #        return redirect(request, 'mediagoblin.plugins.{0}.login'.format(
    #            redirect_name))
    #    else:
    #        return redirect(request, 'index')

    login_form = auth_forms.LoginForm(request.form)
    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')

    login_failed = False

    #if request.method == 'POST' and login_form.validate():
    if request.method == 'POST':
        username = login_form.username.data

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

        #if response.is_valid:

        if login_form.validate():
            user = check_login_simple(username, login_form.password.data)

            goblin = response.is_valid
            if response.error_code:
                _log.warning("reCAPTCHA error: %r", response.error_code)

            #if user:
            if user and goblin:
                # set up login in session
                if login_form.stay_logged_in.data:
                    request.session['stay_logged_in'] = True
                request.session['user_id'] = unicode(user.id)
                request.session.save()

                if request.form.get('next'):
                    return redirect(request, location=request.form['next'])
                else:
                    return redirect(request, "index")
            else:
                messages.add_message(
                    request,
                    messages.WARNING,
                    _('Sorry, captcha was incorrect. Please try again.'))

            login_failed = True

    return render_to_response(
        request,
        'mediagoblin/plugins/recaptcha/login.html',
        {'login_form': login_form,
         'next': request.GET.get('next') or request.form.get('next'),
         'login_failed': login_failed,
         'post_url': request.urlgen('mediagoblin.plugins.recaptcha.login'),
         'allow_registration': mg_globals.app_config["allow_registration"],
         'recaptcha_public_key': config.get('RECAPTCHA_PUBLIC_KEY')})


@allow_registration
@auth_enabled
def register(request):
#    if request.method == 'GET':
#        return redirect(
#            request,
#            'mediagoblin.plugins.recaptcha.register')

    register_form = auth_forms.RegistrationForm(request.form)

    if register_form.validate():
        user = register_user(request, register_form)

        if user:
            # redirect the user to their homepage... there will be a
            # message waiting for them to verify their email
            return redirect(
                request, 'mediagoblin.user_pages.user_home',
                user=user.username)

    return render_to_response(
        request,
        'mediagoblin/plugins/recaptcha/register.html',
        {'register_form': register_form,
         'post_url': request.urlgen('mediagoblin.plugins.recaptcha.register')})
