#!/usr/bin/env python3
from argparse import ArgumentParser
from dataclasses import dataclass, field
import json
from os import environ
from typing import List, Literal, Optional, TypedDict, Union
from urllib import error, parse
from urllib.request import urlopen, Request

@dataclass(init=False)
class ReverbOptions:
    PROG_DESC = 'HTTP echo/mirror utilities scripts'
    ENV_VARS = {'REVERB_SERVER', 'REVERB_DDNS_AUTH', 'REVERB_DDNS_ZONEID',
        'REVERB_DDNS_EMAIL', 'REVERB_DDNS_DOMAIN', 'REVERB_DDNS_SUBDOMAIN'}

    USAGES = {
        'ip': 'Send request to reverb server to discover client\'s public IP address',
        'ddns': 'Perform commands with respect to a (D)DNS provider',
        'ddns-set': "Get public IP & modify a DNS providers' A record with that IP",
        'ddns-list': ("List a DDNS provider's domains or "
            "records for a domain if a --domain arg given"),
        'provider': ('DDNS provider to use ' +
            '[cloudflare|bunny|duck](default: cloudflare)'),
        'ddns_domain': 'Domain name to apply dynamic DNS address to (default: blank)',
        'ddns_zoneid': ('ZoneID for DDNS providers that' +
            'provide IDs to their domains/zones'),
        'server': 'Reverb server URL/address to use (required)',
        'auth': "An API authentication token to use for commnads requiring it",
        'email': "A user email address to use with authentication if required",
        'subdomain': "A subdomain or name to apply DDNS updates to (default: '@')"
    }

    def __init__(self, envars=None, argv=None):
        # Defaults
        self.argparser: Optional[ArgumentParser] = None
        self.root_subcmd: Literal['ip', 'ddns'] = 'ip'
        self.ddns_subcmd: Optional[Literal['list', 'set']] = None
        self.debug: bool = False
        self.reverb_server: Optional[str] = None
        self.ddns_provider: Literal['cloudflare'] = 'cloudflare'
        self.ddns_auth: Optional[str] = None
        self.ddns_email: Optional[str] = None
        self.ddns_zoneid: Optional[str] = None
        self.ddns_domain: Optional[str] = None
        self.ddns_subdomain: Optional[str] = None

        # First parse environment variables
        self.parse_env(envars=envars)

        # Then parse command arguments to override all previous assignments
        self.parse_args(argv=argv)


    def parse_env(self, envars=None):
        for key in self.ENV_VARS:
            if envars is None:
                enval = environ.get(key)
            else:
                enval = envars[key]
            if enval:
                match key:
                    case 'REVERB_SERVER': self.reverb_server = enval
                    case 'REVERB_DDNS_AUTH': self.ddns_auth = enval
                    case 'REVERB_DDNS_EMAIL': self.ddns_email = enval
                    case 'REVERB_DDNS_DOMAIN': self.ddns_domain = enval
                    case 'REVERB_DDNS_ZONEID': self.ddns_zoneid = enval
                    case 'REVERB_DDNS_SUBDOMAIN': self.ddns_subdomain = enval
                    case _:
                        print(f"ERROR: The given environ var of key {key} is invalid")
                        raise KeyError
    
    def parse_args(self, argv=None):
        self.argparser = ArgumentParser(
            prog='reverb', description=self.PROG_DESC)

        # Root subcommands
        subparsers = self.argparser.add_subparsers(
            help='Reverb Subcommands', dest='root_subcmd')

        # 'ip' subcommand subparser added to root of 'subparsers'
        parser_ip = subparsers.add_parser('ip', help=self.USAGES['ip'])
        # 'ip' subcommand options/args/flags
        parser_ip.add_argument('--server', '-s',
            required=True, help=self.USAGES['server'])
        
        # 'ddns' subcommand subparser added to root of 'subparsers'
        # so sub-subcmds after ddns
        parser_ddns = subparsers.add_parser(
            'ddns', help=self.USAGES['ddns'])
        subparser_ddns = parser_ddns.add_subparsers(
            help='DDNS Utilities Sub-Subcommand', dest='ddns_subcmd')
        # 'list' sub-sub added to subcommand 'ddns'
        parser_ddns_list = subparser_ddns.add_parser(
            'list', help=self.USAGES['ddns-list'])
        # arguments for 'list' subsubcommand of ddns > list
        # TODO investigate if --server can be defined near root subcommand parser
        parser_ddns_list.add_argument('--server', '-s', 
            help=self.USAGES['server'])
        parser_ddns_list.add_argument(
            '--provider', '-p', help=self.USAGES['provider'])
        parser_ddns_list.add_argument(
            '--ddns-domain', '-d', type=str, help=self.USAGES['ddns_domain'])
        parser_ddns_list.add_argument(
            '--ddns-zone', '-z', type=str, help=self.USAGES['ddns_zoneid'])
        parser_ddns_list.add_argument(
            '--auth', '-a', type=str, help=self.USAGES['auth'])
        parser_ddns_list.add_argument(
            '--email', '-e', type=str, help=self.USAGES['email'])
        # 'set' sub-subcmd added to subcommand 'ddns'
        parser_ddns_set = subparser_ddns.add_parser(
            'set', help=self.USAGES['ddns-set'])
        # TODO investigate if --server can be defined near root subcommand parser
        parser_ddns_set.add_argument('--server', '-s', 
            help=self.USAGES['server'])
        parser_ddns_set.add_argument(
            '--provider', '-p', help=self.USAGES['provider'])
        parser_ddns_set.add_argument(
            '--ddns-zone', '-z', type=str, help=self.USAGES['ddns_zoneid'])
        parser_ddns_set.add_argument(
            '--ddns-domain', '-d', type=str, help=self.USAGES['ddns_domain'])
        parser_ddns_set.add_argument(
            '--ddns-subdomain', '-n', type=str, help=self.USAGES['subdomain'])
        parser_ddns_set.add_argument(
            '--auth', '-a', type=str, help=self.USAGES['auth'])
        parser_ddns_set.add_argument(
            '--email', '-e', type=str, help=self.USAGES['email'])
        
        args = None
        if argv is None:
            args = self.argparser.parse_args()
        else:
            args = self.argparser.parse_args(argv)
        # if not self.provider
        # provider = DDNSProvider()
        for key in vars(args):
            val = getattr(args, key)
            if val is None:
                continue
            match key:
                case 'root_subcmd': self.root_subcmd = val
                case 'server': self.reverb_server = val
                case 'ddns_subcmd': self.ddns_subcmd = val
                case 'provider': self.ddns_provider = val
                case 'ddns-zone': self.ddns_zoneid = val
                case 'ddns-domain': self.ddns_domain = val
                case 'ddns-subdomain': self.ddns_subdomain = val
                case 'auth': self.ddns_auth = val
                case 'email': self.ddns_email = val
                case other:
                    print(f"ERROR: The given argparsed argument of key {key} is invalid")
                    raise KeyError

@dataclass
class RequestHandler:
    url: str
    method: Literal['GET', 'POST', 'PUT'] = field(default='GET', kw_only=True)
    headers: dict = field(default=None, kw_only=True)
    data: Optional[dict] = field(default=None, kw_only=True)

    def validate_url_schema(self):
        if not ('https://' in self.url or 'http://' in self.url):
            self.url = f"https://{self.url}"
    
    def encode_data(self):
        self.data = json.dumps(self.data)
        self.data = str(self.data)
        self.data = self.data.encode('utf-8')

    def request_data(self):
        self.validate_url_schema()
        if self.headers is None:
            self.headers = {'Accept': 'application/json'}
        ip = None
        req = None
        if self.data is None:
            req = Request(self.url,
                headers=self.headers,
                method=self.method)
        else:
            self.encode_data()
            req = Request(self.url,
                headers=self.headers,
                method=self.method,
                data=self.data)
        try:
            with urlopen(req) as res:
                payload = None
                try:
                    payload = json.loads(res.read().decode())
                except json.JSONDecodeError:
                    print("Error decoding JSON from reverb server")
                    print("The response:")
                    print(res.read().decode())
                    exit(201)
                return payload
        except error.HTTPError as e:
            print(f"Error making request to server {self.url}")
            print(e)
            exit(200)
    

class ReverbClient:
    def __init__(self, envars=None, argv=None):
        self.opts = ReverbOptions(envars=envars, argv=argv)
        self.ddns_provider = DDNSProvider(self.opts)

    def reverb_request_handler(self):
        url = self.opts.reverb_server
        headers = {'Accept': 'application/json'}
        req = RequestHandler(url, headers=headers)
        payload = req.request_data()
        return payload

    def get_public_ip(self) -> Optional[str]:
        res_dict = self.reverb_request_handler()
        headers = res_dict['headers']
        valid_ip_headers_lower = [
            'client-ip',
            'x-forwarded-for',
            'x-forwarded',
            'x-cluster-client-ip',
            'forwarded-for',
            'forwarded',
            'x-real-ip']
        for head in headers:
            if head.lower() in valid_ip_headers_lower:
                ip = res_dict['headers'][head]
                break
        return ip

    def execute(self):
        # First determine first level of subcommands
        if self.opts.root_subcmd == 'ip':
            # If 'ip' subcommand used, run the get_public_ip method
            ip = self.get_public_ip()
            print(f"Your public IP address is: {ip}")
            exit(0)
        elif self.opts.root_subcmd == 'ddns':
            # If 'ddns' subcommand used, check for the next layer of subcommands
            if self.opts.ddns_subcmd == 'list':
                if self.ddns_provider.subdomain is None:
                    # If no subdomain is provided, assume listing zone records
                    zones = self.ddns_provider.list_zones()
                    print("Here are the zones configured for provider:")
                    print(json.dumps(zones, indent=2))
                    exit(0)
                # If there is a subdomain given then get the records for it
                records = self.ddns_provider.list_zone_records()
                print(f"Here are the records for {self.ddns_provider.domain}:")
                print(json.dumps(records, indent=2))
                exit(0)
            elif self.opts.ddns_subcmd == 'set':
                ip = self.get_public_ip()
                result = self.ddns_provider.set_record(ip)
                print("Successfuly updated url URLHERE to point to IPHERE")
                print(json.dumps(result, indent=2))
            else:
                self.argparser.error("Invalid subcommand given after 'ddns' subcommand")
        else:
            self.argparser.error("Error, invalid subcommand given")

class DDNSProvider:
    # TODO: Should be an abstract or have abstract methods to subclass
    def __init__(self, opts: ReverbOptions):
        self.name: Literal['cloudflare'] = opts.ddns_provider
        self.auth_token: Optional[str] = opts.ddns_auth
        self.auth_email: Optional[str] = opts.ddns_email
        self.zoneid: Optional[str] = opts.ddns_zoneid
        self.domain: Optional[str] = opts.ddns_domain
        self.subdomain: Optional[str] = opts.ddns_subdomain
        self.recordid: Optional[str] = None
        self.payload_zones: Optional[dict] = None
    
    def get_url(self):
        # TODO: This needs changing for other DNS providers
        return 'https://api.cloudflare.com/client/v4/zones'
    
    def cloudflare_request_handler(self, url, data=None, method='GET'):
        headers = {
            'Accept': 'application/json',
            'Authorization': f"Bearer {self.auth_token}"
        }
        req = RequestHandler(url, method=method, headers=headers, data=data)
        payload = req.request_data()
        return payload

    def list_zones(self):
        url = self.get_url()
        payload = self.cloudflare_request_handler(url)
        self.payload_zones = payload['result']
        return self.payload_zones

    def list_zone_records(self):
        # If no domain or zoneid given, we can't search a domain
        if self.domain is None and self.zoneid is None:
            print(("Options Error: Can't search for a zone/domain record without"
                + "specifying a zone or domain!"))
            exit(210)
        # If a zoneid isn't given but a domain name is, 
        if self.zoneid is None:
            # we have to list zones and search for a domain in there
            zones = self.list_provider_domains()
            for zone in zones:
                # Found the zone with the domain in it
                if self.domain in zone['name']:
                    self.zoneid = zone['id']
            print(("Options Error: Couldn't find a zone " +
                f"with domain name {self.domain}!"))
            exit(211)
        
        # By now we know a zoneid exists
        # So list the records for that zoneid
        url = f"{self.get_url()}/{self.zoneid}/dns_records"
        payload = self.cloudflare_request_handler(url)
        payload_records = payload['result']
        self.domain = payload_records[0]['zone_name']
        return payload_records
    
    def get_subdomain_record(self):
        zone_records = self.list_zone_records()
        # If subdomain is root ie "@", then on cloudflare...
        # the zone_name is going to be the same as the record name
        is_root = False
        if self.subdomain == '@':
            is_root = True
        for record in zone_records:
            record_name = record['name']
            if is_root:
                if self.domain in record_name:
                    self.recordid = record['id']
                    return record
            else:
                if self.subdomain in record_name:
                    self.recordid = record['id']
                    return record
        print("Provider Error, no record for that subdomain found")
        print("Here are the records available:")
        print(zone_records)
        exit(220)


    def set_record(self, content, type='A', proxied=False, ttl=300):
        self.get_subdomain_record()
        url = f"{self.get_url()}/{self.zoneid}/dns_records/{self.recordid}"
        data = {
            'name': self.subdomain,
            'type': type,
            'content': content,
            'proxied': False,
            'ttl': ttl,
        }
        payload = self.cloudflare_request_handler(
            url, method='PUT', data=data)
        return payload
        
def main():
    # Parse the args
    # config: ReverbClientConfig = parse_config()
    # config_subcommands_handler(config)
    client = ReverbClient()
    client.execute()

if __name__ == '__main__':
    main()
