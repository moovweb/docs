/**
 * Copyright 2019 The AMP HTML Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS-IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const config = require('@lib/config');
const {get} = require('@lib/utils/credentials');
const randomString = require('randomstring');

// eslint-disable-next-line new-cap
const examples = express.Router();
examples.use(cookieParser());

const OAUTH_COOKIE = 'oauth2_cookie';
const OAUTH_ID = 'google_client_id';
const OAUTH_SECRET = 'google_client_secret';
const OAUTH_CONFIG = {
  scopes: 'openid profile',
  state: randomString.generate(8),
};

examples.all('/login/google', googleLogin);
examples.all('/callback/google', googleCallback);

async function googleLogin(request, response) {
  const returnUrl = request.query ? request.query.return : '';
  response.cookie(OAUTH_COOKIE, {returnUrl});
  OAUTH_CONFIG.id = await get(OAUTH_ID)
      .then((credential) => {
        return credential;
      })
      .catch(() => {
        response.status(400).send('Invalid OAuth2 credentials');
      });
  response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?response_type=code&scope=${OAUTH_CONFIG.scopes}&client_id=${OAUTH_CONFIG.id}&redirect_uri=${config.hosts.platform.base}/documentation/examples/personalization/oauth2_login/callback/google&state=${OAUTH_CONFIG.state}`);
}

async function googleCallback(request, response) {
  OAUTH_CONFIG.secret = await get(OAUTH_SECRET)
      .then((credential) => {
        return credential;
      })
      .catch(() => {
        response.status(400).send('Invalid OAuth2 credentials');
      });
  const token = request.query.code;
  const state = request.query.state;
  if (!token) {
    response.status(400).send('Missing OAuth2 code');
  }
  if (state !== OAUTH_CONFIG.state) {
    response.status(400).send('Invalid OAuth2 state');
    return;
  }
  axios({
    method: 'post',
    url: `https://accounts.google.com/o/oauth2/token?grant_type=authorization_code&client_id=${OAUTH_CONFIG.id}&client_secret=${OAUTH_CONFIG.secret}&code=${token}&redirect_uri=${config.hosts.platform.base}/documentation/examples/personalization/oauth2_login/callback/google`,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  }).then((res) => {
    getNameFromToken(response, request, res.data.access_token);
  }).catch(() => {
    response.redirect(generateReturnURL(request.cookies[OAUTH_COOKIE], false));
  });
}

function getNameFromToken(response, request, token) {
  axios({
    method: 'get',
    url: 'https://www.googleapis.com/oauth2/v3/userinfo',
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  }).then((res) => {
    // eslint-disable-next-line max-len
    response.cookie(OAUTH_COOKIE, Object.assign(request.cookies[OAUTH_COOKIE], {loggedInWith: 'google', name: res.data.name}));
    response.redirect(generateReturnURL(request.cookies[OAUTH_COOKIE], true));
  }).catch(() => {
    response.redirect(generateReturnURL(request.cookies[OAUTH_COOKIE], false));
  });
}

function generateReturnURL(cookie, success = false) {
  return `${cookie.returnUrl}#success=${success}`;
}

module.exports = examples;
