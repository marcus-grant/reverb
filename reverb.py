#!/usr/bin/env python3
from argparse import ArgumentParser
from dataclasses import dataclass, field
import json
from os import environ
from typing import List, Literal, Optional, TypedDict, Union
from urllib.request import urlopen, Request
import urllib.error

@dataclass
class DDNSProvider:
    VALID_PROVIDERS = Literal['cloudflare']#, 'duck', 'bunny']
    auth_token: str = field(default='')
    auth_email: str = field(default='')
    # domains: List[str]  # TODO in future, make this a seperate class for records
    name: VALID_PROVIDERS = field(default='cloudflare')

@dataclass(init=False)
class ReverbClient:
    ENV_PREFIX = 'REVERB_'
    ENV_VARS = {'REVERB_SERVER', 'REVERB_AUTH',
        'REVERB_EMAIL', 'REVERB_DOMAIN', 'REVERB_SUBDOMAIN'}
    PROG_NAME = 'reverb'
    PROG_DESC = 'HTTP echo/mirror utilities scripts'
    VALID_SUBCMDS = Literal['ip', 'ddns']
    VALID_DDNS_SUBCMDS = Literal['list', 'set']
    USAGES = {
        'ip': 'Send request to reverb server to discover client\'s public IP address',
        'ddns': 'Perform commands with respect to a (D)DNS provider',
        'ddns-set': "Get public IP & modify a DNS providers' A record with that IP",
        'ddns-list': ("List a DDNS provider's domains or "
            "records for a domain if a --domain arg given"),
        'provider': ('DDNS provider to use ' +
            '[cloudflare|bunny|duck](default: cloudflare)'),
        'domain': 'Domain name to apply dynamic DNS address to (default: blank)',
        'server': 'Reverb server URL/address to use (required)',
        'auth': "An API authentication token to use for commnads requiring it",
        'email': "A user email address to use with authentication if required",
        'ddns-subdomain': "A subdomain or name to apply DDNS updates to (default: '@')"
    }
    server: str
    subcommands: VALID_SUBCMDS
    ddns_subcommands: VALID_DDNS_SUBCMDS
    provider: DDNSProvider = field(default_factory=DDNSProvider)
    debug: bool = field(default=False)
    domain: str = field(default='')
    subdomain: str = field(default='@')

    def __init__(self):
        # defaults
        self.debug = False
        self.domain = ''
        self.subdomain = '@'
        self.provider = DDNSProvider()
        self.parse_env()
        self.argparser = None
        self.parse_args()
        # TODO: Add validate step

    def parse_args(self, argv=None):
        self.argparser = ArgumentParser(
            prog=self.PROG_NAME, description=self.PROG_DESC)

        # Root subcommands
        subparsers = self.argparser.add_subparsers(
            help='Reverb Subcommands', dest='subcommands')

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
            help='DDNS Utilities Sub-Subcommand', dest='ddns_subcommands')
        # 'list' sub-sub added to subcommand 'ddns'
        parser_ddns_list = subparser_ddns.add_parser(
            'list', help=self.USAGES['ddns-list'])
        # arguments for 'list' subsubcommand of ddns > list
        # TODO investigate if --server can be defined near root subcommand parser
        parser_ddns_list.add_argument('--server', '-s', 
            required=True, help=self.USAGES['server'])
        parser_ddns_list.add_argument(
            '--provider', '-p', help=self.USAGES['provider'])
        parser_ddns_list.add_argument(
            '--domain', '-d', type=str, help=self.USAGES['domain'])
        parser_ddns_list.add_argument(
            '--auth', '-a', type=str, help=self.USAGES['auth'])
        parser_ddns_list.add_argument(
            '--email', '-e', type=str, help=self.USAGES['email'])
        # 'set' sub-subcmd added to subcommand 'ddns'
        parser_ddns_set = subparser_ddns.add_parser(
            'set', help=self.USAGES['ddns-set'])
        # TODO investigate if --server can be defined near root subcommand parser
        parser_ddns_set.add_argument('--server', '-s', 
            required=True, help=self.USAGES['server'])
        parser_ddns_set.add_argument(
            '--provider', '-p', help=self.USAGES['provider'])
        parser_ddns_set.add_argument(
            '--domain', '-d', type=str, help=self.USAGES['domain'])
        parser_ddns_set.add_argument(
            '--subdomain', '-n', type=str, help=self.USAGES['subdomain'])
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
        for key in args:
            match key:
                case 'subcommands': self.subcommands = args[key]
                case 'server': self.server = args[key]
                case 'ddns_subcommands': self.ddns_subcommands = args[key]
                case 'provider': self.provider.name = args[key]
                case 'domain': self.domain = args[key]
                case 'subdomain': self.subdomain = args[key]
                case 'auth': self.provider.auth_token = args[key]
                case 'email': self.provider.auth_email = args[key]
                case other:
                    print(f"ERROR: The given argparsed argument of key {key} is invalid")
                    raise KeyError

    def parse_env(self, env=None):
        for key in self.ENV_VARS:
            if env is None:
                enval = environ.get(key)
            else:
                enval = env[key]
            if enval:
                match key:
                    case 'REVERB_SERVER': self.server = enval
                    case 'REVERB_AUTH': self.provider.auth_token = enval
                    case 'REVERB_EMAIL': self.provider.auth_email = enval
                    case 'REVERB_DOMAIN': self.domain = enval
                    case 'REVERB_SUBDOMAIN': self.subdomain = enval
                    case other:
                        print(f"ERROR: The given environ var of key {key} is invalid")
                        raise KeyError
    
    def reverb_request_handler(self):
        url = self.server
        if (not 'https://' in url) or (not 'http://' in url):
            url = f"https://{url}"
        headers = {'Accept': 'application/json'}
        ip = None
        req = Request(url, headers=headers)
        try:
            with urlopen(req) as res:
                body = None
                try:
                    body = json.loads(res.read().decode())
                except json.JSONDecodeError:
                    print("Error decoding JSON from reverb server")
                    print("The response:")
                    print(res.read().decode())
                    exit(201)
                return body
        except urllib.error.HTTPError as e:
            # body = json.load(res.read().decode())
            print(f"Error making request to server {url}")
            print(e)
            exit(200)

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

    def list_provider_domains(self):
        pass

    def list_provider_domain_records(self):
        pass

    def set_provider_ddns_record(self):
        pass

    def execute(self):
        # First determine first level of subcommands
        if self.subcommands == 'ip':
            # If 'ip' subcommand used, run the get_public_ip method
            self.get_public_ip()
        elif self.subcommands == 'ddns':
            # If 'ddns' subcommand used, check for the next layer of subcommands
            if self.ddns_subcommands == 'list':
                if self.domain == '':
                    self.list_provider_domains()
                else:
                    self.list_provider_domain_records()
            elif self.ddns_subcommands == 'set':
                self.set_provider_ddns_record()
            else:
                self.argparser.error("Invalid subcommand given after 'ddns' subcommand")
        else:
            self.argparser.error("Error, invalid subcommand given")


        
# Handle configs and call appropriate functions
# def config_subcommands_handler(config: ReverbClientConfig):
#     if config['debug']:
#         print('Inside config_subcommands_handler with config...')
#         print(config)
#     subcommands = config['subcommands']
#     match subcommands:
#         case 'ip':
#             ip = get_public_ip(config)
#             if not ip is None:
#                 print(ip)
#                 exit(0)
#             else:
#                 print_ip_fail(config, ip)
#                 exit(1)
#         case 'ddns':
#             ip = get_public_ip(config)
#             if not ip is None:
#                 msg = set_ddns(config, ip)
#                 if 'SUCCESS' in msg:
#                     print(msg)
#                     exit(0)
#                 print('Problem setting DDNS record in cloudflare, response:')
#                 print(msg)
#                 exit(4)
#             print("ERROR getting public IP, quiting")
#             exit(1)
#         case _:
#             raise ValueError('Error in parsing subcommands!')

# def validate_config_hostname(config: ReverbClientConfig) -> str:
#     hostname = config['hostname']
#     if not 'http://' in hostname or not 'https://' in hostname:
#         hostname = f"https://{hostname}"
#     return hostname


# def print_ip_fail(config: ReverbClientConfig):
#     print("IP was not retrieved from this reverb server")
#     print("Here is the ReverbClientConfig for debugging")
#     print(config)
#     exit(2)

# # TODO: Add config params for subdomain (name), ttl
# # TODO: Break this up into individual functions for each DNS provider
# def set_ddns(config: ReverbClientConfig, ip: str) -> str:
#     # look here for API details
#     # https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record
#     zoneid = config['zoneid']
#     auth = config['auth']
#     url = f"https://api.cloudflare.com/client/v4/zones/{zoneid}/dns_records"
#     headers = {
#         'Content-Type': 'application/json',
#         'Authorization': f"Bearer {auth}"
#     }
#     data = {
#         'type': 'A',
#         'comment': 'DDNS A record set',
#         'content': str(ip),
#         'proxied': False,
#         'name': '@',
#         'ttl': 300,

#     }
#     req_data = json.dumps(data).encode()
#     req = Request(url, method='POST', headers=headers, data=req_data)
#     try:
#         with urlopen(req) as res:
#             body = json.load(res.read().decode())
#             return f"SUCCESS with body {body}"
#     except urllib.error.HTTPError as e:
#         # body = json.load(res.read().decode())
#         return str(e)
#     # with urlopen(req) as res:
#     #     if res.status == 200:
#     #         return 'SUCCESS'
#     #     elif res.status in range(400, 500):
#     #         body = json.load(res.read().decode())
#     #         return f"FAIL: {body}"
#     #     else:
#     #         print("ERROR: Invalid cloudflare response code, exiting")
#     #         exit(3)

def main():
    # Parse the args
    # config: ReverbClientConfig = parse_config()
    # config_subcommands_handler(config)
    client = ReverbClient()
    client.execute()

if __name__ == '__main__':
    main()
