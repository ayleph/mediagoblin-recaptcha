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
import wtforms

from mediagoblin.tools.translate import lazy_pass_to_ugettext as _
from mediagoblin.auth.tools import normalize_user_or_email_field

#from wtfrecaptcha.fields import RecaptchaField

class RegistrationForm(wtforms.Form):
    username = wtforms.StringField(
        _('Username'),
        [wtforms.validators.Required(),
         normalize_user_or_email_field(allow_email=False)])
    password = wtforms.PasswordField(
        _('Password'),
        [wtforms.validators.Required(),
         wtforms.validators.Length(min=5, max=1024)])
    email = wtforms.StringField(
        _('Email address'),
        [wtforms.validators.Required(),
         normalize_user_or_email_field(allow_user=False)])
    #recaptcha_response_field = wtforms.HiddenField('')
    recaptcha_response_field = wtforms.StringField(
        _('CAPTCHA'))
    recaptcha_challenge_field = wtforms.HiddenField('')
