from zope.interface import implements, classProvides
from letsencrypt.plugins.common import Plugin
from letsencrypt.interfaces import IAuthenticator, IPluginFactory
from letsencrypt import errors

from acme.challenges import DNS01

import dns
import dns.query
import dns.tsigkeyring
import dns.tsig
import dns.update
import sys
import json
import time

keyalgorithms = {
    'hmac-md5': dns.tsig.HMAC_MD5,
    'hmac-sha1': dns.tsig.HMAC_SHA1,
    'hmac-sha224': dns.tsig.HMAC_SHA224,
    'hmac-sha256': dns.tsig.HMAC_SHA256,
    'hmac-sha384': dns.tsig.HMAC_SHA384,
    'hmac-sha512': dns.tsig.HMAC_SHA512
}

class Authenticator(Plugin):
    implements(IAuthenticator)
    classProvides(IPluginFactory)

    description = "Let`s Encrypt DNS Update (RFC 2136) Authenticator"

    @classmethod
    def add_parser_arguments(cls, add):
        add("tsigkeyfile", metavar="FILE", default=None,
            help="Path to a JSON file containing the tsig key data (name, algorithm and secret).")
        add("nameserver", metavar="SERVER", default=None,
            help="The nameserver to send updates to.")
        add("zone", metavar="ZONE", default=None,
            help="The zone to send updates to.")

    def prepare(self):
        if not self.conf("tsigkeyfile"):
            raise errors.PluginError("The tsigkeyfile argument is required to perform dns updates.")
        if not self.conf("nameserver"):
            raise errors.PluginError("The nameserver argument is required to perform dns updates.")
        tsig_data = json.load(open(self.conf("tsigkeyfile")))
        if 'name' not in tsig_data:
            raise errors.PluginError("The key name is not specified in the tsigkey file.")
        if 'algorithm' not in tsig_data:
            raise errors.PluginError("The key algorithm is not specified in the tsigkey file.")
        if 'secret' not in tsig_data:
            raise errors.PluginError("The key secret is not specified in the tsigkey file.")
        self.keyring = dns.tsigkeyring.from_text({tsig_data['name']: tsig_data['secret']})
        self.keyalgorithm = keyalgorithms[tsig_data['algorithm']]

    def more_info(self):
        return """Use DNS Update (RFC 2136), also sometimes called dyndns, to perform the identification challenge."""

    def get_chall_pref(self, domain):
        return [DNS01]

    def zone_and_record(self, request_domain, challenge_name):
        zone = self.conf("zone") if self.conf("zone") else request_domain
        if challenge_name[0 - len(zone):] != zone:
            raise errors.PluginError("Domain to verify is not in the zone we can update.")
        record = challenge_name + '.'
        return zone, record

    def perform(self, achalls):
        return [self._perform_single(achall) for achall in achalls]

    def _perform_single(self, achall):
        response, validation = achall.response_and_validation()
        zone, record = self.zone_and_record(achall.domain, achall.validation_domain_name(achall.domain))

        update = dns.update.Update(zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm)
        update.add(record, 300, 'TXT', validation.encode('ascii'))
        dns.query.tcp(update, self.conf('nameserver'))

        return response

    def cleanup(self, achalls):
        return [self._cleanup_single(achall) for achall in achalls]

    def _cleanup_single(self, achall):
        response, validation = achall.response_and_validation()
        zone, record = self.zone_and_record(achall.domain, achall.validation_domain_name(achall.domain))

        update = dns.update.Update(zone, keyring=self.keyring, keyalgorithm=self.keyalgorithm)
        update.delete(record, 'TXT', validation.encode('ascii'))
        dns.query.tcp(update, self.conf('nameserver'))
