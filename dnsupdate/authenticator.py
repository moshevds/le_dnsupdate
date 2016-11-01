"""DNS Update (RFC 2136) plugin."""
from collections import namedtuple
from shlex import shlex
from itertools import takewhile
import re

from zope.interface import implements, classProvides
import dns
import dns.tsig
import dns.tsigkeyring
import dns.update

from acme import challenges

from certbot.interfaces import IAuthenticator, IPluginFactory
from certbot import errors
from certbot.plugins.common import Plugin


Key = namedtuple('Key', ['ring', 'algorithm'])
DnsNames = namedtuple('DnsNames', ['domain', 'zone', 'record', 'nameserver'])

key_data_regex = re.compile(
    r'key(.*){\s*algorithm(.*);\s*secret(.*);\s*};', re.MULTILINE | re.DOTALL)


def named_conf_key_parse(filename):
    """Parse a keyfile created by following the ddns-confgen instuctions."""
    try:
        with open(filename) as keyfile:
            key_data = keyfile.read()
    except IOError:
        return None
    key_data = key_data_regex.match(key_data)
    if key_data is None:
        return None

    name = key_data.group(1).strip(' "')
    algorithm = key_data.group(2).strip(' "')
    secret = key_data.group(3).strip(' "')

    try:
        ring = dns.tsigkeyring.from_text({name: secret})
    except:
        return None
    algorithm = dns.name.from_text(algorithm)
    return Key(ring, algorithm)


def send_dns_update(dns_names, key, want_record, value):
    """Send a DNS Update to the nameserver."""
    update = dns.update.Update(dns_names.zone, "IN", key.ring, keyalgorithm=key.algorithm)
    if want_record:
        update.add(dns_names.record, 300, "TXT", value)
    else:
        update.delete(dns_names.record, "TXT", value)
    dns.query.tcp(update, dns_names.nameserver)


def soa_for_name(domain):
    """Return the best soa record for the domain."""
    return dns.resolver.query(dns.resolver.zone_for_name(domain), "SOA")


class Authenticator(Plugin):
    """DNS Update (RFC 2136) Authenticator.

    This plugin uses RFC 2136 update queries for solving dns-01 challenges and
    requires access to a named.conf-style key file only. The man page for
    nsupdate(8) contains extensive documentation about the key file and DNS
    Update in general.
    """
    classProvides(IPluginFactory)
    implements(IAuthenticator)

    description = "Let`s Encrypt DNS Update (RFC 2136) Authenticator"

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.key = None

    @classmethod
    def add_parser_arguments(cls, add):
        add("keyfile", metavar="FILE", default=None,
            help="Path to a JSON file containing the tsig key data (name, algorithm and secret).")
        add("nameserver", metavar="SERVER", default=None,
            help="The nameserver to send updates to.")
        add("zone", metavar="ZONE", default=None,
            help="The zone to send updates to.")

    def prepare(self):
        """Prepare the plugin."""
        if not self.conf("keyfile"):
            raise errors.MisconfigurationError(
                "The keyfile argument is required to perform dns updates.")
        self.key = named_conf_key_parse(self.conf("keyfile"))

    def more_info(self):
        """Human-readable string to help the user."""
        return ("Use DNS Update (RFC 2136), also sometimes called dyndns, to "
                "perform the identification challenge.")

    def get_chall_pref(self, domain):
        """Return list of challenge preferences."""
        return [challenges.DNS01]


    def _one_update(self, want_record, achall):
        domain = dns.name.from_text(achall.domain)

        zone = self.conf("zone")
        if zone is None:
            soa_answer = soa_for_name(domain)
            zone = soa_answer.qname
        else:
            zone = dns.name.from_text(zone)
            soa_answer = soa_for_name(zone)

        validation_domain_name = achall.validation_domain_name(achall.domain)
        record = dns.name.from_text(validation_domain_name)

        nameserver = self.conf("nameserver")
        if nameserver is None:
            nameserver = soa_answer[0].mname.to_text()

        dns_names = DnsNames(domain, zone, record, nameserver)

        response, validation = achall.response_and_validation()
        send_dns_update(dns_names, self.key, want_record, validation)
        return response

    def perform(self, achalls):
        """Perform the given challenge."""
        return [self._one_update(True, achall) for achall in achalls]

    def cleanup(self, achalls):
        """Revert changes and shutdown after challenges complete."""
        return [self._one_update(False, achall) for achall in achalls]
