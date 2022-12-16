#!/usr/bin/env python3
from argparse import ArgumentParser
from typing import List, Literal, Optional, TypedDict
# import time
# import socket
# import ipaddress
# import urllib

### Typing ###
SUBCOMMAND = Literal['serve', 'request', 'ip']

def main():
    # Parse the args
    config: ReverbServerConfig = parse_config()
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
