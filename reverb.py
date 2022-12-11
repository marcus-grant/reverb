#!/usr/bin/env python3

from argparse import ArgumentParser
from flask import Flask, request
from os import environ
from typing import List, Literal, Optional, TypedDict
# import time
# import socket
# import ipaddress
# import urllib

### Typing ###
SUBCOMMAND = Literal['serve', 'request', 'ip']

ReverbConfig = TypedDict('ReverbConfig', {
    'subcommands': Optional[List[SUBCOMMAND]],
    'port': int,
    'host': str,
    'debug': Optional[bool],
})

DEFAULTS: ReverbConfig = {
    'subcommands': None,
    'port': 33333,
    'host': '0.0.0.0',
    'debug': False,
}

ENV_PREFIX = 'REVERB_'

def validate_config(config: ReverbConfig):
    if config['port'] < 1 or config['port'] >= 2**16:
        raise Exception("Listening port must be between 1 & 65535")

def parse_env(config: ReverbConfig) -> ReverbConfig:
    config_envar = [f"{ENV_PREFIX}{k.upper()}" for k in DEFAULTS.keys()]
    for var_name in config_envar:
        var = environ.get(var_name)
        if var:
            config_key = var_name.removeprefix(ENV_PREFIX).lower()
            match config_key:
                case 'port': # int keys
                    config[config_key] = int(var)
                case 'debug': # bool keys
                    config[config_key] = True
                case 'subcommands': # ignore these cases
                    break
                case _: # The default str case
                    config[config_key] = var
    return config

def parse_args(config: ReverbConfig) -> ReverbConfig:
    # Root argument parser
    parser = ArgumentParser(prog='reverb',
        description='HTTP echo/mirror client & server')
    subparsers = parser.add_subparsers(
        help='Commands to run reverb as server', dest='subcommands')
    # Server subcommand argument parsers
    server_parser = subparsers.add_parser('serve')
    server_parser.add_argument(
        '--port',
        '-p',
        type=int,
        # default=DEFAULTS['port'],
        help=f"Port for server to listen to (default: {DEFAULTS['port']})")
    server_parser.add_argument(
        '--host',
        # default=DEFAULTS['host'],
        help=f"Host to listen to listens to self (default: {DEFAULTS['host']})")
    server_parser.add_argument(
        '--debug',
        # '-d',
        # type=bool,
        # default=DEFAULTS['debug'],
        action='store_true',
        help=f"Run server in debug mode (defaults: {DEFAULTS['debug']}")
    # self.configs = self.parser.parse_args()
    args = parser.parse_args()
    for key in args.__dict__:
        if args.__dict__[key] is not None:
            if args.__dict__[key] != DEFAULTS[key]:
                config[key] = args.__dict__[key]

    # config: ReverbConfig = {
    #     'subcommands': args.subcommands,
    #     'port': args.port,
    #     'host': args.host,
    #     'debug': args.debug,
    # }
    return config

# Setup argparsers
def parse_config() -> ReverbConfig:
    config = parse_args(parse_env(DEFAULTS))
    validate_config(config)
    return config


### Flask ###
# Create flask app
server = Flask(__name__)

# Index Route
@server.route('/')
def echo_root():
    # Get the request line
    # request_line =
    # f"{request.method} {request.path} {request.environ['SERVER_PROTOCOL']}"
    # TODO: Include configuration for base URL
    request_line = f"({request.path})"

    # Get request method
    request_method = request.method

    # Get the request headers
    headers = dict(request.headers)

    # Get body data, but first check for its size, could eat up memory
    # TODO: Make the content_length configurable
    body_len = request.content_length
    body_data = None
    if not not body_len:
        if body_len > 10000000:
            body_data = request.get_data()
    
    # Get the request cookies
    cookies = dict(request.cookies)

    # Create a response
    # TODO: If the request headers indicate a browser, render HTML
    response = {
        'request_line': request_line,
        'method': request_method,
        'headers': headers,
        'body_data': body_data,
        'cookies': cookies,
    }
    return response
        
# @server.route('/')
# def get_ip(self):
#     """
#     Instead of mirroring request entirely, get IP address of sender
#     """
#     print(self.request.headers)

def main():
    # Parse the args
    config: ReverbConfig = parse_config()
    # TODO: Client subcommand parser
    if 'serve' in config['subcommands']:
        server.run(
            host=config['host'],
            port=config['port'],
            debug=config['debug'],
            use_reloader=config['debug'],
        )
    elif 'request' in config.subcommands:
        # TODO: Implement various request verbs as nested subcommands
        # But first implement IP
        pass


if __name__ == '__main__':
    main()
