/*
    Copyright 2020 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

package com.google.googleidentity.oauth2.token;

import com.google.googleidentity.oauth2.request.OAuth2Request;

import java.util.List;
import java.util.Optional;

/** The class for generate token, refresh token, read token, store token */
public interface OAuth2TokenService {

  /** Generate an access token for the request. */
  OAuth2AccessToken generateAccessToken(OAuth2Request request);

  /**
   * Try to refresh the access token related to the refresh token string. If token cannot be found,
   * return empty.
   */
  Optional<OAuth2AccessToken> refreshToken(String refreshToken);

  /**
   * Read the token information related to the access token string. If token cannot be found, return
   * empty.
   */
  Optional<OAuth2AccessToken> readAccessToken(String accessToken);

  /**
   * Read the token information related to the refresh token string. If token cannot be found,
   * return empty.
   */
  Optional<OAuth2RefreshToken> readRefreshToken(String refreshToken);

  /** Revoke by access token, if token cannot be found or the token is expired, return false. */
  boolean revokeByAccessToken(String accessToken);

  /** Revoke by refresh token, if token cannot be found, return false. */
  boolean revokeByRefreshToken(String refreshToken);

  /** Revoke tokens between a user and a client, if token cannot be found, return false */
  boolean revokeUserClientTokens(String username, String clientID);

  /** List all client linked by this user */
  List<String> listUserClient(String username);

  /** List all access tokens between a user and a client */
  List<OAuth2AccessToken> listUserClientAccessTokens(String username, String clientID);

  /** List all refresh tokens between a user and a client */
  List<OAuth2RefreshToken> listUserClientRefreshTokens(String username, String clientID);

  void reset();
}
