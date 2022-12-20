import argparse
import unittest
from unittest.mock import Mock, MagicMock, patch
from unittest import TestCase
import sys

import reverb as rb
import reverb_secrets

class TestReverbClientIPCmd(TestCase):
    test_argv = ['ip', reverb_secrets.hostname]
    expect_subcmd = 'ip'
    expect_hostname = reverb_secrets.hostname
    sys.argv = ['reverb.py', 'ip', reverb_secrets.hostname]
    config: rb.ReverbClientConfig = rb.parse_config()
    # Mocking reverb-server response


    # define the 'ip' option here
    # parse the arguments
    def test_ip_subcmd_args(self):
        self.assertEqual('ip', self.config['subcommands'])
        self.assertEqual(reverb_secrets.hostname, self.config['hostname'])

    # TODO: Test subcommand_handler that it calls the right funcs
    # def check_called(func):
    #     return Mock(side_effect=func)

    # def test_subcommand_handler(self):
    #     cfg_handler_mock = 
    #     cfg_handler2 = rb.Request

    # def test_get_public_ip_request(self):
    #     test_body_res = {
    #         'X-Forwarded-For': '123.123.123.123',
    #     }
    #     actual = rb.get_public_ip(self.config)
        
