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

import re
import os
import json
import shutil
import logging
import urllib.parse
import tempfile
import requests

from git import Repo, GitCommandError
from functools import wraps
from flask_github import GitHub
from flask_sslify import SSLify
from flask import (Flask, Markup, session, request, url_for, redirect, flash,
                   render_template, abort)


GITHUB_API_BASE = 'https://api.github.com'

DIFF_GIT_RE = re.compile(r'^(diff --git a/)([^ ]+) b/([^ ]+)$', re.M)

PLUGINS_RE = re.compile(r'.*/(plugins|modules|module_utils)/(.+)/(.+)$')

# This regex makes sure that a file in a PR can be migrated
# docs/
# test/
# changelog/
# lib/ansible/plugins/
# lib/ansible/modules/
# lib/ansible/module_utils/
VALID_FILE = re.compile(
    r'^(lib/ansible/(plugins|modules|module_utils)|test|changelogs|docs)/'
)

app = Flask('prmove')
try:
    app.config.from_envvar('PRMOVE_CONFIG')
except Exception:
    app.config['GITHUB_CLIENT_ID'] = ''
    app.config['GITHUB_CLIENT_SECRET'] = ''
github = GitHub(app)
sslify = SSLify(app)

LOG = logging.getLogger('prmove')


class Mover(object):
    def __init__(self, token, username, pr_url, repo, close_original=False,
                 keepdirs=False, webapp=True):
        self.username = username
        self.token = token
        self.pr_url = pr_url.rstrip('/')
        self.repo = repo.rstrip('/')
        self.close_original = close_original
        self.keepdirs = keepdirs
        self.upstream_branch = None

        self.urlparts = urllib.parse.urlparse(self.pr_url)
        self.repo_parts = urllib.parse.urlparse(self.repo)

        self.target_repo = self.repo_parts.path.split('/')[2]
        self.upstream_account = self.repo_parts.path.split('/')[1]

        self.branch_name = self.urlparts.path.split('/', 2)[-1]
        self.patch = None

        self.working_dir = tempfile.mkdtemp()

        self.original_pull_request_url = '%s/repos%s' % (
            GITHUB_API_BASE, self.urlparts.path.replace('/pull/', '/pulls/'))

        self.original_pull_request = None
        self.is_migration_by_owner = None

        self.webapp = webapp

    def _headers_params(self):
        params = {}
        headers = {}
        if self.webapp:
            params['access_token'] = self.token
        else:
            headers['Authorization'] = 'token %s' % self.token

        return params, headers

    def check_already_migrated(self):

        params, headers = self._headers_params()

        url = '%s/repos/%s/%s/branches/%s' % (GITHUB_API_BASE, self.username, self.target_repo, self.branch_name)

        r = requests.get(url, params=params, headers=headers)

        if r.status_code == 404:
            return

        if r.status_code == 200:
            raise Exception('Branch %s already exists. Has this pull request already been migrated?' %
                            self.branch_name)

        r.raise_for_status()

    def get_original_pull_request(self):
        params, headers = self._headers_params()

        r = requests.get(self.original_pull_request_url, params=params, headers=headers)
        r.raise_for_status()
        self.original_pull_request = r.json()
        self.mergeable_state = self.original_pull_request['mergeable_state']
        self.is_migration_by_owner = self.original_pull_request['user']['login'] == self.username

        return self.original_pull_request

    def get_patch(self):
        r = requests.get('%s.patch' % self.pr_url)
        r.raise_for_status()
        self.patch = r.text


        changes = set()
        for m in DIFF_GIT_RE.finditer(self.patch):
            line = m.group(0)
            path = m.group(3)

            if not VALID_FILE.search(path):
                raise Exception('Invalid path for a collection: %s' % path)

            plugin_match = PLUGINS_RE.search(path)
            if plugin_match:
                path_list = ['plugins']
                is_module = plugin_match.group(1) in ('modules', 'module_utils')
                if is_module:
                    path_list.append(plugin_match.group(1))
                else:
                    path_list.append(plugin_match.group(2))
                if self.keepdirs and is_module:
                    path_list.append(plugin_match.group(2))
                path_list.append(plugin_match.group(3))
                new_path = '/'.join(path_list)
                changes.add((path, new_path))
            else:
                if path.startswith('test/'):
                    new_path = re.sub('^test/', 'tests/', path)
                else:
                    new_path = path
                changes.add((path, new_path))

        for change in changes:
            if change[0] == change[1]:
                continue

            self.patch = re.sub(re.escape(change[0]), change[1], self.patch)

        with open('%s/patch.patch' % self.working_dir, 'w+') as f:
            f.write(self.patch)

        return self.patch

    def clone_repo(self):
        clone_dir = '%s/repo' % self.working_dir
        origin_url = 'https://%s@github.com/%s/%s.git' % (self.token, self.username, self.target_repo)
        upstream_url = 'https://github.com/%s/%s.git' % (self.upstream_account, self.target_repo)

        user_repo = '%s/%s' % (self.username, self.target_repo)

        try:
            clone = Repo.clone_from(origin_url, clone_dir)
        except GitCommandError as e:
            raise Exception('Failed to open clone of %s repository:',
                            '\n%s\n%s' % (user_repo, e.stdout, e.stderr)) from e

        try:
            self.upstream_branch = clone.active_branch.name
        except GitCommandError as e:
            raise Exception('Failed to get active branch from %s repository:',
                            '\n%s\n%s' % (user_repo, e.stdout, e.stderr)) from e

        try:
            upstream = clone.create_remote('upstream', upstream_url)
        except GitCommandError as e:
            raise Exception('Failed to add upstream to clone of %s repository:'
                            '\n%s\n%s' % (user_repo, e.stdout, e.stderr)) from e

        try:
            if requests.get(origin_url).status_code != 200:
                raise Exception('You must have a fork of %s at: %s' % (user_repo, self.username, self.target_repo, origin_url))
        except GitCommandError as e:
            raise Exception('Failed to verify origin exists:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            upstream.fetch()
            clone.git.checkout('upstream/%s' % clone.active_branch.name, b=self.branch_name)
        except GitCommandError as e:
            raise Exception('Failed to create new branch:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            clone.git.am('%s/patch.patch' % self.working_dir, '--3way')
        except GitCommandError as e:
            raise Exception('Failed to apply patch:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

        try:
            clone.git.push(['origin', self.branch_name])
        except GitCommandError as e:
            raise Exception('Failed to push new branch for pull request:'
                            '\n%s\n%s' % (e.stdout, e.stderr)) from e

    def create_pull_request(self):
        params, headers = self._headers_params()

        data = {
            'title': self.original_pull_request['title'],
            'body': self.original_pull_request['body'],
            'head': '%s:%s' % (self.username, self.branch_name),
            'base': self.upstream_branch,
        }

        url = '%s/repos/%s/%s/pulls' % (GITHUB_API_BASE, self.upstream_account, self.target_repo)
        r = requests.post(url, data=json.dumps(data), params=params, headers=headers)
        r.raise_for_status()

        pull = r.json()

        comment = {
            'body': 'Migrated from %s' % self.original_pull_request['html_url']
        }

        if not self.is_migration_by_owner:
            comment['body'] += ' by %s (not original author)' % self.username

        r = requests.post(pull['comments_url'], data=json.dumps(comment),
                          params=params, headers=headers)
        r.raise_for_status()

        return pull

    def close_original_pull_request(self):
        if not self.close_original:
            return None

        params, headers = self._headers_params()

        data = {
            'state': 'closed'
        }

        r = requests.post(self.original_pull_request_url, data=json.dumps(data), params=params, headers=headers)
        r.raise_for_status()

    def __enter__(self):
        return self

    def __exit__(self, ex_type, value, traceback):
        try:
            shutil.rmtree(self.working_dir)
        except OSError:
            LOG.exception('Failure removing working dir: %s' %
                          self.working_dir)


@github.access_token_getter
def token_getter():
    return session.get('token')


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('token'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped


@app.before_first_request
def logger():
    app.logger.addHandler(logging.StreamHandler())
    app.logger.setLevel(logging.INFO)
    app.logger.handlers.extend(logging.getLogger("gunicorn.error").handlers)


@app.errorhandler(500)
def internal_server_error(e):
    app.logger.exception(e)
    return abort(500)


@app.route('/')
def index():
    if session.get('token'):
        return redirect('/move')

    return render_template('index.html')


@app.route('/login')
def login():
    return github.authorize(scope='user:email public_repo')


@app.route('/login/authorized')
@github.authorized_handler
def authorized(oauth_token):
    if oauth_token is None:
        flash('Authorization failed.', 'danger')
        return redirect('index')

    session['token'] = oauth_token
    session.update(github.get('user'))
    return redirect(url_for('move'))


@app.route('/move', methods=['GET', 'POST'])
def move():
    if request.method == 'POST':
        try:
            move_post()
        except MarkupException as e:
            LOG.exception(e)
            flash(Markup(e.markup), 'danger')
        except Exception as e:
            LOG.exception(e)
            flash(e, 'danger')

    return render_template('move.html')


def move_post(token=None, login=None, pr_url=None, repo=None,
              close_original=None, keepdirs=None):
    pr_url = pr_url or request.form.get('prurl')
    repo = repo or request.form.get('repo')
    keepdirs = keepdirs or request.form.get('keepdirs') == '1'
    close_original = close_original or request.form.get('closeorig') == '1'
    token = token or session.get('token')
    login = login or session.get('login')

    with Mover(token, login, pr_url, repo, close_original, keepdirs) as mover:
        mover.check_already_migrated()

        try:
            mover.get_original_pull_request()
        except Exception as e:
            raise Exception('Failure validating pull request (%s) for %s: %s' %
                            (pr_url, login, e)) from e

        try:
            mover.get_patch()
        except Exception as e:
            raise Exception('Failure getting patch (%s) for %s: %s' %
                            (pr_url, login, e)) from e

        try:
            mover.clone_repo()
        except Exception as e:
            raise Exception('Failure handling git repository (%s) for %s: %s' %
                            (pr_url, login, e)) from e

        try:
            pull = mover.create_pull_request()
        except Exception as e:
            raise Exception('Failure creating pull request (%s) for %s: %s' %
                            (pr_url, login, e)) from e

        flash(
            Markup('Your pull request has been migrated to '
                   '<a href="%(html_url)s">%(html_url)s</a>' % pull),
            'success'
        )

        try:
            mover.close_original_pull_request()
        except Exception as e:
            raise Exception('Failure closing original pull request (%s) for %s: %s' %
                            (pr_url, login, e)) from e


class MarkupException(Exception):
    def __init__(self, markup):
        super(MarkupException, self).__init__(markup)
        self.markup = markup


if __name__ == '__main__':
    app.run('0.0.0.0', 5000, debug=True)
