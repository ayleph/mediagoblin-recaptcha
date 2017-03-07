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

from mediagoblin import messages
from mediagoblin.tools import pluginapi
from mediagoblin.tools.translate import lazy_pass_to_ugettext as _
from recaptcha.client import captcha

import json
import urllib2

_log = logging.getLogger(__name__)


def extra_validation(register_form):
    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')
    recaptcha_private_key = config.get('RECAPTCHA_PRIVATE_KEY')

    if 'g_recaptcha_response' in register_form:
        recaptcha_response = register_form.g_recaptcha_response.data
        if recaptcha_response == u'':
            for raw_data in register_form.g_recaptcha_response.raw_data:
                if raw_data != u'':
                    recaptcha_response = raw_data

    if 'remote_address' in register_form:
        remote_address = register_form.remote_address.data
        if remote_address == u'':
            for raw_data in register_form.remote_address.raw_data:
                if raw_data != u'':
                    remote_address = raw_data

    captcha_challenge_passes = False

    if recaptcha_response:
        url = "https://www.google.com/recaptcha/api/siteverify?secret=%s&response=%s&remoteip=%s" % (recaptcha_private_key, recaptcha_response, remote_address)
        response = json.loads(urllib2.urlopen(url).read())
        captcha_challenge_passes = response['success']

    if not captcha_challenge_passes:
        register_form.g_recaptcha_response.errors.append(
            _('Sorry, CAPTCHA attempt failed.'))
        _log.debug('captcha response is: %r', recaptcha_response)
        _log.debug('remote address is: %r', remote_address)
        _log.debug('server response is: %r' % response)

    return captcha_challenge_passes
