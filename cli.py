#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2016 Matt Martz
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import argparse
import os

from prmove import move_post


parser = argparse.ArgumentParser()
parser.add_argument('--token', default=os.getenv('GITHUB_TOKEN'),
                    help='GitHub OAuth Token')
parser.add_argument('--login', default=os.getenv('GITHUB_LOGIN'),
                    help='GitHub Login')
parser.add_argument('--close', action='store_true',
                    help='Close Original PR')
parser.add_argument('--keepdirs', action='store_true',
                    help='Keep module sub directories')
parser.add_argument('pull_request', help='Pull Request URL')
parser.add_argument('repo', help='Target Repo')
args = parse.parse_args()


move_post(args.token, args.login, args.pull_request, args.repo,
          args.close, args.keepdirs)
