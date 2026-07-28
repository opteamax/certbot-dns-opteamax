"""Certbot Authenticator Plugin for Opteamax DNS.

@author:     Peter Lieven <pl@opteamax.de>
@license:    GPL

"""
import logging
import json
import time

from typing import List
from acme import challenges
from certbot import interfaces, errors
from certbot import achallenges
from certbot.plugins import common
from certbot.plugins import dns_common
from certbot.display import util as display_util
from urllib.request import urlopen, Request

logger = logging.getLogger(__name__)

OXAPI_URL = "https://www.opteamax.de/oxapi/dns/"
REQUEST_TIMEOUT_S = 60
DNS_RECORD_TTL_S = 300
VALIDATION_TIMEOUT_S = DNS_RECORD_TTL_S * 1.5
VALIDATION_RETRY_INT_S = 10
DNS_UPDATE_CHECK_ENABLED = True

try:
    import dns.resolver
    import dns.name
    import dns.query
    import dns.message
    import dns.exception
except ImportError:
    VALIDATION_TIMEOUT_S = 180
    logger.warning(f"certbot-dns-opteamax requires dnspython module to be installed for live dns update checks. falling back to static timeout of {VALIDATION_TIMEOUT_S} seconds.")
    DNS_UPDATE_CHECK_ENABLED = False

class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Opteamax DNS

    This Authenticator uses the Opteamax OXAPI API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record (if you are '
                   'using Opteamax for DNS).')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super().add_parser_arguments(add, default_propagation_seconds=180)
        add('credentials', help='Opteamax OXAPI credentials INI file.')

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'Opteamax OXAPI credentials INI file',
            {
                'username':      'OXAPI Username',
                'password':      'OXAPI Password',
            }
        )

    def more_info(self):
        return ('This plugin configures a DNS TXT record to respond to a '
                'dns-01 challenge using the Opteamax OXAPI.')

    def _call_oxapi(self, command: str, data: dict) -> dict:
        url = f"{OXAPI_URL}{command}"
        logger.debug(f"_call_oxapi: calling {url} with {data}")
        req = Request(url)
        req.add_header('Content-Type', 'application/json')
        try:
            with urlopen(req, json.dumps(data).encode('utf-8'), REQUEST_TIMEOUT_S) as res:
                response_data = res.read().decode('utf-8')
                logger.debug(f"_call_oxapi: response -> {response_data}\n")
                json_res = json.loads(response_data)
        except Exception as e:
            raise errors.PluginError(f"Error communicating with OXAPI: {e}")

        if isinstance(json_res, dict) and json_res.get('errno') is not None and int(json_res['errno']) != 0:
            raise errors.PluginError(f"OXAPI returned error: {json_res}")
        return json_res

    def _build_ox_auth(self):
        return {'user': self.credentials.conf("username"), 'passwd': self.credentials.conf("password")}

    def _get_ox_domid(self, domain: str) -> (int, str, str):
        logger.debug("_get_ox_domid: domain %s", domain)
        params = { 'auth': self._build_ox_auth(), 'with_ptr': False }
        res = self._call_oxapi('get_zones', params)
        domid = 0
        longestMatch = ""
        for row in res:
            suffixLen = len(row['domain']) + 1
            if (suffixLen > len(domain)):
                continue
            suffix = domain[-suffixLen:]
            if (suffix == "." + row['domain']):
                if (len(row['domain']) > len(longestMatch)):
                    longestMatch = row['domain']
                    domid = row['domain_id']
        if (domid == 0):
            raise errors.PluginError(
                f"Could not find OXAPI domid for certificate domain: {domain}")
        localPart = domain[0:len(domain) - len(longestMatch) - 1]
        logger.debug("_get_ox_domid: found id %d for localPart '%s' longestMatch '%s'", domid, localPart, longestMatch)
        return (domid, longestMatch, localPart)

    def _rm_ox_record(self, dataid) -> None:
        logger.debug("_rm_ox_record: dataid %d", dataid)
        params = { 'auth': self._build_ox_auth(), 'record': dataid }
        self._call_oxapi('delete_record', params)

    def _rm_ox_txt_rr(self, domid, localPart) -> None:
        logger.debug("_rm_ox_txt_rr: domid %d localPart %s", domid, localPart)
        params = { 'auth': self._build_ox_auth(), 'domain_id': domid }
        res = self._call_oxapi('get_entries', params)
        for row in res['data']:
            if (row['subdomain'] == localPart):
                logger.debug('_rm_ox_txt_rr: need to delete orphan RR %d subdomain %s target %s', row['dataid'], row['subdomain'], row['target'])
                self._rm_ox_record(row['dataid'])

    def _add_ox_txt_rr(self, domid, fqdn, text) -> None:
        logger.debug("_add_ox_txt_rr: domid %d fqdn %s text %s", domid, fqdn, text)
        data = {
            'type' : 'TXT',
            'fqdn' : fqdn,
            'text' : text,
            'ttl' : DNS_RECORD_TTL_S,
            'id' : 0,
        }
        params = { 'auth': self._build_ox_auth(), 'domainid': domid, 'data' : json.dumps(data) }
        self._call_oxapi('save_record', params)

    def perform(self, achalls: List[achallenges.AnnotatedChallenge]
                ) -> List[challenges.ChallengeResponse]: # pylint: disable=missing-function-docstring
        self._setup_credentials()

        self._attempt_cleanup = True

        responses = []
        validations = []

        # perform DNS updates
        for achall in achalls:
            domain = achall.domain
            validation_domain_name = achall.validation_domain_name(domain)
            validation = achall.validation(achall.account_key)

            logger.debug("_perform: domain %s validation_domain_name %s validation %s", domain, validation_domain_name, validation)
            (domid, longestMatch, localPart) = self._get_ox_domid(validation_domain_name)
            self._add_ox_txt_rr(domid, validation_domain_name, validation)

            validations.append((longestMatch, validation_domain_name, validation))
            responses.append(achall.response(achall.account_key))

        if not DNS_UPDATE_CHECK_ENABLED:
            display_util.notify(f"Waiting {VALIDATION_TIMEOUT_S} seconds for DNS updates to propagate.")
            time.sleep(VALIDATION_TIMEOUT_S)
            return responses

        # verify if all updates have been propagated to all authoritative DNS servers
        validation_start_time = time.time()
        for longestMatch, validation_domain_name, validation in validations:
            ns_list = self.get_authoritative_nameservers(longestMatch)
            display_util.notify(f"Waiting for DNS updates to propagate for domain '{validation_domain_name}' on nameservers: {ns_list}.")
            while True:
                if self.check_txt_on_authoritative_servers(longestMatch, validation_domain_name, validation):
                    display_util.notify(f"DNS update validation succeeded for domain '{validation_domain_name}' after {int(time.time() - validation_start_time)} seconds.")
                    break
                if time.time() - validation_start_time >= VALIDATION_TIMEOUT_S:
                    logger.error(f"DNS update validation failed for domain '{validation_domain_name}' after {int(time.time() - validation_start_time)} seconds.")
                    break
                time.sleep(VALIDATION_RETRY_INT_S)

        # return responses in any case even if some updates have failed.
        return responses

    def _perform(self, domain, validation_domain_name, validation):
        logger.debug("_perform: domain %s validation_domain_name %s validation %s", domain, validation_domain_name, validation)
        (domid, longestMatch, localPart) = self._get_ox_domid(validation_domain_name)
        self._add_ox_txt_rr(domid, validation_domain_name, validation)

    def _cleanup(self, domain, validation_domain_name, validation):
        logger.debug("_cleanup: domain %s validation_domain_name %s validation %s", domain, validation_domain_name, validation)
        (domid, longestMatch, localPart) = self._get_ox_domid(validation_domain_name)
        self._rm_ox_txt_rr(domid, localPart)

    def get_authoritative_nameservers(self, domain):
        try:
            ns_response = dns.resolver.resolve(domain, 'NS')
            return [str(rdata.target).rstrip('.') for rdata in ns_response]
        except Exception as e:
            logger.error(f"Could not get NS records for domain '{domain}': {e}")
            return []

    def get_nameserver_ips(self, ns_list):
        ns_ips = {}
        for ns in ns_list:
            try:
                a_response = dns.resolver.resolve(ns, 'A')
                ns_ips[ns] = [rdata.address for rdata in a_response]
            except Exception as e:
                logger.error(f"Could not resolve A record for {ns}: {e}")
        return ns_ips

    def query_txt_from_ns(self, domain, ns_ip):
        try:
            query = dns.message.make_query(domain, dns.rdatatype.TXT)
            response = dns.query.udp(query, ns_ip, timeout=2)
            txt_records = []
            for answer in response.answer:
                if answer.rdtype == dns.rdatatype.TXT:
                    for rdata in answer:
                        txt_records.append(b''.join(rdata.strings).decode())
            return txt_records
        except Exception as e:
            logger.error(f"TXT query from {ns_ip} for domain '{domain}' failed: {e}")
            return []

    def check_txt_on_authoritative_servers(self, domain, validation_domain_name, validation):
        ns_list = self.get_authoritative_nameservers(domain)
        ns_ips = self.get_nameserver_ips(ns_list)
        msg = f"checking TXT record '{validation_domain_name}'"
        ret = True
        for ns, ips in ns_ips.items():
            for ip in ips:
                txts = self.query_txt_from_ns(validation_domain_name, ip)
                if validation in txts:
                    msg += f": {ns} ({ip}) [OK] "
                else:
                    msg += f": {ns} ({ip}) [FAIL] "
                    ret = False
        if ret:
            display_util.notify(msg)
        else:
            logger.warning(msg)

        return ret
