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


/**
 * The class for generate token, refresh token, read token, store token
 */
public interface OAuth2TokenService {

    /**
     * Generate an access token for the request.
     */
    OAuth2Token generateAccessToken(OAuth2Request request);

    /**
     * Try to refresh the access token related to the refresh token string.
     * If no related token, return null.
     */
    Optional<OAuth2Token> refreshToken(String refreshToken);

    /**
     * Read the token information related to the access token string.
     * If no related token, return null.
     */
    Optional<OAuth2Token> readByAccessToken(String accessToken);

    /**
     * Read the token information related to the refresh token string.
     * If no related token, return null.
     */
    Optional<OAuth2Token> readByRefreshToken(String refreshToken);

    /**
     * Revoke access token, if no that token, return false.
     */
    boolean revokeAccessToken(String accessToken);

    /**
     * Revoke refresh token, if no that token, return false.
     */
    boolean revokeRefreshToken(String refreshToken);

    /**
     * List all client linked by this user
     */
    public List<String> listUserClient(String username);

    /**
     *  List all tokens between a user and a client
     */
    List<OAuth2Token> listUserClientTokens(String username, String clientID);
}
