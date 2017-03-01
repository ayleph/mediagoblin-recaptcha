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

import urllib2
import json

_log = logging.getLogger(__name__)


def captcha_challenge(request):
    captcha_challenge_passes = False

    config = pluginapi.get_config('mediagoblin.plugins.recaptcha')
    recaptcha_private_key = config.get('RECAPTCHA_PRIVATE_KEY')
    recaptcha_response = request.form['g-recaptcha-response']
    remote_addr = request.remote_addr

    url = "https://www.google.com/recaptcha/api/siteverify?secret=%s&response=%s&remoteip=%s" % (recaptcha_private_key, recaptcha_response, remote_addr)
    response = json.loads(urllib2.urlopen(url).read())
    captcha_challenge_passes = response['success']

    if not captcha_challenge_passes:
        _log.debug('response is: %r', recaptcha_response)
        _log.debug('remote address is: %r', remote_addr)
        messages.add_message(
            request,
            messages.WARNING,
            _('Sorry, captcha was incorrect. Please try again.'))

    return captcha_challenge_passes
