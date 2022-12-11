#!/usr/bin/env python3

import argparse
from flask import Flask, request
from typing import List, Literal, Optional, TypedDict, Union
import time
import socket
import ipaddress
import urllib

### Typing ###
SUBCOMMAND = Literal['serve', 'request', 'ip']

ReverbConfig = TypedDict('ReverbConfig', {
    'subcommands': List[SUBCOMMAND],
    'port': int,
    'host': str,
    'debug': Optional[bool],
})

def validate_config(config: ReverbConfig):
    if config['port'] < 1 or config['port'] >= 2**16:
        raise Exception("Listening port must be between 1 & 65535")
    
# Setup argparsers
def parse_config():
    # Root argument parser
    parser = argparse.ArgumentParser(prog='reverb',
        description='HTTP echo/mirror client & server')
    subparsers = parser.add_subparsers(
        help='Commands to run reverb as server', dest='subcommands')
    # Server subcommand argument parsers
    server_parser = subparsers.add_parser('serve')
    server_parser.add_argument(
        '--port',
        '-p',
        type=int,
        default=33333,
        help='Port for server to listen to (default: 33333)')
    server_parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='Port for server to listen to (default: 0.0.0.0)')
    server_parser.add_argument(
        '--debug',
        # '-d',
        # type=bool,
        default=False,
        action='store_true',
        help='Run server in debug mode')
    # self.configs = self.parser.parse_args()
    args = parser.parse_args()
    config: ReverbConfig = {
        'subcommands': args.subcommands,
        'port': args.port,
        'host': args.host,
        'debug': args.debug,
    }
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
