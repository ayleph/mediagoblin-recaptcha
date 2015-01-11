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

from mediagoblin.tools import pluginapi
from recaptcha.client import captcha

_log = logging.getLogger(__name__)


def validate_captcha(recaptcha_challenge, recaptcha_response, remote_addr):
    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')
    recaptcha_private_key = config.get('RECAPTCHA_PRIVATE_KEY')
    captcha_is_validated = False

    response = captcha.submit(
        recaptcha_challenge,
        recaptcha_response,
        recaptcha_private_key,
        remote_addr,
    )

    captcha_is_validated = response.is_valid
    if response.error_code:
        _log.debug('reCAPTCHA error: %r', response.error_code)
        _log.debug('response field is: %r', recaptcha_response)
        _log.debug('challenge field is: %r', recaptcha_challenge)

    return captcha_is_validated
