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

import com.google.common.collect.ImmutableList;
import com.google.googleidentity.oauth2.request.OAuth2Request;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.UUID;
import java.util.Date;
import java.util.Optional;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default in memory token service.
 * An implementation of {@link OAuth2TokenService}
 */
public class InMemoryOAuth2TokenService implements OAuth2TokenService {

    private Map<String, OAuth2Token> accessTokenMap = new ConcurrentHashMap<>();
    private Map<String, OAuth2Token> refreshTokenMap = new ConcurrentHashMap<>();

    private boolean isRefreshTokenRotatable = false;

    private long tokenValidTime = 10 * 60l;

    /**
     * Used to get all tokens between a user and a client when a user want to revoke
     * all tokens with that client.
     */
    Map<String, HashMap<String, Set<OAuth2Token>>> userClientTokenMap =
            new ConcurrentHashMap<>();

    public InMemoryOAuth2TokenService(){
    }

    public InMemoryOAuth2TokenService(boolean isRefreshTokenRotatable, long tokenValidTime){
        this.isRefreshTokenRotatable = isRefreshTokenRotatable;
        this.tokenValidTime = tokenValidTime;
    }

    public OAuth2Token generateAccessToken(OAuth2Request request) {
        String accessTokenValue = UUID.randomUUID().toString();
        while (accessTokenMap.containsKey(accessTokenValue)) {
            accessTokenValue = UUID.randomUUID().toString();
        }
        OAuth2Token.Builder builder =
                OAuth2Token.newBuilder()
                        .setAccessToken(accessTokenValue)
                        .setClientId(request.getRequestAuth().getClientId())
                        .setUsername(request.getRequestAuth().getUsername())
                        .setIsScoped(request.getRequestBody().getIsScoped())
                        .addAllScopes(request.getRequestBody().getScopesList())
                        .setRefreshable(request.getRequestBody().getRefreshable())
                        .setIsRefreshTokenRotatable(isRefreshTokenRotatable);

        if (request.getRequestBody().getRefreshable()) {
            String refreshTokenValue = UUID.randomUUID().toString();
            while (refreshTokenMap.containsKey(refreshTokenValue)) {
                refreshTokenValue = UUID.randomUUID().toString();
            }
            builder.setRefreshToken(refreshTokenValue);
        }

        OAuth2Token token =
                builder.setExpiredTime((new Date().getTime())/1000l + tokenValidTime).build();
        accessTokenMap.put(accessTokenValue, token);
        if (token.getRefreshable()) {
            refreshTokenMap.put(token.getRefreshToken(), token);
        }

        if (!userClientTokenMap.containsKey(token.getUsername())) {
            userClientTokenMap.put(token.getUsername(),
                    new HashMap<String, Set<OAuth2Token>>());
        }

        if (!userClientTokenMap.get(token.getUsername()).containsKey(token.getClientId())) {
            userClientTokenMap.get(token.getUsername())
                    .put(token.getClientId(), new HashSet<OAuth2Token>());
        }

        userClientTokenMap.get(token.getUsername()).get(token.getClientId()).add(token);

        return token;
    }

    public Optional<OAuth2Token> refreshToken(String refreshToken) {
        if (refreshTokenMap.containsKey(refreshToken)) {

            OAuth2Token token = refreshTokenMap.get(refreshToken);

            accessTokenMap.remove(token.getAccessToken());

            userClientTokenMap.get(token.getUsername())
                    .get(token.getClientId()).remove(token);

            String accessTokenValue = UUID.randomUUID().toString();
            while (accessTokenMap.containsKey(accessTokenValue)) {
                accessTokenValue = UUID.randomUUID().toString();
            }

            OAuth2Token newToken =
                    OAuth2Token.newBuilder(token)
                            .setAccessToken(accessTokenValue)
                            .setExpiredTime((new Date().getTime())/1000l + tokenValidTime)
                            .build();

            accessTokenMap.put(accessTokenValue, newToken);
            refreshTokenMap.put(refreshToken,  newToken);
            userClientTokenMap.get(token.getUsername()).get(token.getClientId())
                    .add(newToken);

            return Optional.ofNullable(newToken);
        }
        else {
            return Optional.empty();
        }
    }

    public Optional<OAuth2Token> readByAccessToken(String accessToken) {
        return Optional.ofNullable(accessTokenMap.get(accessToken));
    }

    public Optional<OAuth2Token> readByRefreshToken(String refreshToken) {
        return Optional.ofNullable(refreshTokenMap.get(refreshToken));
    }

    public boolean revokeAccessToken(String accessToken) {
        if (accessTokenMap.containsKey(accessToken)) {
            OAuth2Token token = accessTokenMap.get(accessToken);
            accessTokenMap.remove(accessToken);
            if (token.getRefreshable()) {
                refreshTokenMap.remove(token.getRefreshToken());
            }
            userClientTokenMap.get(token.getUsername()).get(token.getClientId())
                    .remove(accessToken);
            return true;
        }
        else {
            return false;
        }
    }

    public boolean revokeRefreshToken(String refreshToken) {
        if (refreshTokenMap.containsKey(refreshToken)) {
            OAuth2Token token = refreshTokenMap.get(refreshToken);
            refreshTokenMap.remove(refreshToken);
            userClientTokenMap.get(token.getUsername()).get(token.getClientId()).remove(token);

            OAuth2Token newToken =
                    OAuth2Token.newBuilder(token).setRefreshable(false).build();
            accessTokenMap.put(newToken.getAccessToken(), newToken);
            userClientTokenMap.get(token.getUsername()).get(token.getClientId()).add(newToken);

            return true;
        }
        else {
            return false;
        }
    }

    public List<String> listUserClient(String username) {
        if(!userClientTokenMap.containsKey(username)){
            return ImmutableList.of();
        }
        else {
            HashMap<String, Set<OAuth2Token>> map = userClientTokenMap.get(username);
            if (map.isEmpty()) {
                return ImmutableList.of();
            }
            List<String> clientList = new ArrayList<String>();
            for (Map.Entry<String, Set<OAuth2Token>> entry : map.entrySet()) {
                if (!entry.getValue().isEmpty()) {
                    clientList.add(entry.getKey());
                }
            }
            return ImmutableList.copyOf(clientList);
        }
    }

    @Override
    public List<OAuth2Token> listUserClientTokens(String username, String clientID) {
        if (!userClientTokenMap.containsKey(username)) {
            return ImmutableList.of();
        }
        else if (!userClientTokenMap.get(username).containsKey(clientID)) {
                return ImmutableList.of();
        }
        else {
            return ImmutableList.copyOf(userClientTokenMap.get(username).get(clientID));
        }
    }


}
