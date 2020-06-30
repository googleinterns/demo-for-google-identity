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

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Store user tokens in memory
 */
public final class UserTokens {

    private final String username;

    private static final class ClientTokens {
        private final String clientID;
        private Optional<OAuth2RefreshToken> refreshToken = Optional.empty();
        private final Map<String, OAuth2AccessToken> tokenMap = new ConcurrentHashMap<>();

        ClientTokens(String clientID) {
            this.clientID = clientID;
        }

        public Optional<OAuth2AccessToken> readAccessToken(String tokenValue) {
            return Optional.ofNullable(tokenMap.get(tokenValue));
        }

        public void addAccessToken(String tokenValue, OAuth2AccessToken token) {
            tokenMap.put(tokenValue, token);
        }

        public void setRefreshToken(OAuth2RefreshToken token) {
            refreshToken = Optional.ofNullable(token);
        }

        public Optional<OAuth2RefreshToken> getRefreshToken() {
            return refreshToken;
        }

        public Optional<OAuth2RefreshToken> readRefreshToken(String tokenString) {
            if (refreshToken.isPresent() &&
                    refreshToken.get().getRefreshToken().equals(tokenString)) {
                return refreshToken;
            } else {
                return Optional.empty();
            }
        }

        public void clearExpiredTokens() {
            for (Map.Entry<String, OAuth2AccessToken> token : tokenMap.entrySet()) {
                if (Instant.ofEpochSecond(token.getValue().getExpiredTime())
                        .isBefore(Instant.now())) {
                    tokenMap.remove(token.getKey());
                }
            }
        }

        public boolean isEmpty() {
            return tokenMap.isEmpty() && !refreshToken.isPresent();
        }

        public List<OAuth2AccessToken> listAccessTokens(){
            return ImmutableList.copyOf(tokenMap.values());
        }
    }

    Map<String, ClientTokens> clientTokensMap = new ConcurrentHashMap<>();


    UserTokens(String username){
        this.username = username;
    }

    public Optional<OAuth2AccessToken> readAccessToken(String clientID, String tokenValue) {
        if (clientTokensMap.containsKey(clientID)) {
            return clientTokensMap.get(clientID).readAccessToken(tokenValue);
        } else {
            return Optional.empty();
        }
    }

    public void addAccessToken(String clientID, String tokenValue, OAuth2AccessToken token) {
        if (!clientTokensMap.containsKey(clientID)) {
            clientTokensMap.put(clientID, new ClientTokens(clientID));
        }
        clientTokensMap.get(clientID).addAccessToken(tokenValue, token);
    }

    public void setRefreshToken(String clientID, OAuth2RefreshToken token) {
        if (!clientTokensMap.containsKey(clientID)) {
            clientTokensMap.put(clientID, new ClientTokens(clientID));
        }
        clientTokensMap.get(clientID).setRefreshToken(token);
    }

    public Optional<OAuth2RefreshToken> getRefreshToken(String clientID) {
        if (clientTokensMap.containsKey(clientID)) {
            return clientTokensMap.get(clientID).getRefreshToken();
        } else {
            return Optional.empty();
        }
    }

    public Optional<OAuth2RefreshToken> readRefreshToken(String clientID, String tokenString) {
        if (clientTokensMap.containsKey(clientID)) {
            return clientTokensMap.get(clientID).readRefreshToken(tokenString);
        } else {
            return Optional.empty();
        }
    }

    public void clearExpiredTokens() {
        for (Map.Entry<String, ClientTokens> client : clientTokensMap.entrySet()) {
            client.getValue().clearExpiredTokens();
            if (client.getValue().isEmpty()) {
                clientTokensMap.remove(client.getKey());
            }
        }
    }

    public boolean isEmpty() {
        return clientTokensMap.isEmpty();
    }

    public List<String> listClients(){
        return ImmutableList.copyOf(clientTokensMap.keySet());
    }

    public List<OAuth2AccessToken> listAccessTokens(String clientID){
        if (clientTokensMap.containsKey(clientID)) {
            return clientTokensMap.get(clientID).listAccessTokens();
        } else {
            return ImmutableList.of();
        }
    }

    public boolean revokeUserClientTokens(String clientID){
        boolean result = clientTokensMap.containsKey(clientID);
        clientTokensMap.remove(clientID);
        return result;
    }

}
