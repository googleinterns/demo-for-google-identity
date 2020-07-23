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

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;

import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Store user tokens in memory */
public final class UserTokens {

  private final String username;
  Map<String, ClientTokens> clientTokensMap = new ConcurrentHashMap<>();

  UserTokens(String username) {
    this.username = username;
  }

  public Optional<OAuth2AccessToken> readAccessToken(String clientID, String tokenValue) {
    if (clientTokensMap.containsKey(clientID)) {
      return clientTokensMap.get(clientID).readAccessToken(tokenValue);
    } else {
      return Optional.empty();
    }
  }

  public void addAccessToken(String clientID, OAuth2AccessToken token) {
    if (!clientTokensMap.containsKey(clientID)) {
      clientTokensMap.put(clientID, new ClientTokens(clientID));
    }
    clientTokensMap.get(clientID).addAccessToken(token);
  }

  public void addRefreshToken(String clientID, OAuth2RefreshToken token) {
    if (!clientTokensMap.containsKey(clientID)) {
      clientTokensMap.put(clientID, new ClientTokens(clientID));
    }
    clientTokensMap.get(clientID).addRefreshToken(token);
  }

  public List<OAuth2RefreshToken> listRefreshTokens(String clientID) {
    if (clientTokensMap.containsKey(clientID)) {
      return clientTokensMap.get(clientID).listRefreshTokens();
    } else {
      return ImmutableList.of();
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

  public List<String> listClients() {
    return ImmutableList.copyOf(clientTokensMap.keySet());
  }

  public List<OAuth2AccessToken> listAccessTokens(String clientID) {
    if (clientTokensMap.containsKey(clientID)) {
      return clientTokensMap.get(clientID).listAccessTokens();
    } else {
      return ImmutableList.of();
    }
  }

  public boolean revokeByAccessToken(OAuth2AccessToken accessToken) {
    if (Strings.isNullOrEmpty(accessToken.getRefreshToken())) {
      clientTokensMap
          .get(accessToken.getClientId())
          .accessTokenMap
          .remove(accessToken.getAccessToken());
      return true;
    } else {
      Optional<OAuth2RefreshToken> refreshToken =
          clientTokensMap
              .get(accessToken.getClientId())
              .readRefreshToken(accessToken.getRefreshToken());
      if (!refreshToken.isPresent()) {
        return false;
      }
      return revokeByRefreshToken(refreshToken.get());
    }
  }

  public boolean revokeByRefreshToken(OAuth2RefreshToken refreshToken) {
    for (String accessToken :
        clientTokensMap
            .get(refreshToken.getClientId())
            .refreshTokenMap
            .get(refreshToken.getRefreshToken())
            .accessTokens) {
      clientTokensMap.get(refreshToken.getClientId()).accessTokenMap.remove(accessToken);
    }
    clientTokensMap
        .get(refreshToken.getClientId())
        .refreshTokenMap
        .remove(refreshToken.getRefreshToken());
    return true;
  }

  public boolean revokeUserClientTokens(String clientID) {
    boolean result = clientTokensMap.containsKey(clientID);
    clientTokensMap.remove(clientID);
    return result;
  }

  private static final class ClientTokens {

    private final String clientID;
    private final Map<String, OAuth2AccessToken> accessTokenMap = new ConcurrentHashMap<>();
    private final Map<String, TokenGroup> refreshTokenMap = new ConcurrentHashMap<>();

    ClientTokens(String clientID) {
      this.clientID = clientID;
    }

    public Optional<OAuth2AccessToken> readAccessToken(String tokenValue) {
      return Optional.ofNullable(accessTokenMap.get(tokenValue));
    }

    public void addAccessToken(OAuth2AccessToken token) {
      accessTokenMap.put(token.getAccessToken(), token);
      if (!Strings.isNullOrEmpty(token.getRefreshToken())) {
        refreshTokenMap.get(token.getRefreshToken()).getAccessTokens().add(token.getAccessToken());
      }
    }

    public void addRefreshToken(OAuth2RefreshToken token) {
      refreshTokenMap.put(token.getRefreshToken(), new TokenGroup(token));
    }

    public Optional<OAuth2RefreshToken> readRefreshToken(String tokenString) {
      if (refreshTokenMap.containsKey(tokenString)) {
        return Optional.of(refreshTokenMap.get(tokenString).getRefreshToken());
      } else {
        return Optional.empty();
      }
    }

    public void clearExpiredTokens() {
      for (Map.Entry<String, OAuth2AccessToken> token : accessTokenMap.entrySet()) {
        if (Instant.ofEpochSecond(token.getValue().getExpiredTime()).isBefore(Instant.now())) {
          if (!Strings.isNullOrEmpty(token.getValue().getRefreshToken())) {
            refreshTokenMap
                .get(token.getValue().getRefreshToken())
                .getAccessTokens()
                .remove(token.getKey());
          }
          accessTokenMap.remove(token.getKey());
        }
      }
    }

    public boolean isEmpty() {
      return accessTokenMap.isEmpty() && refreshTokenMap.isEmpty();
    }

    public List<OAuth2RefreshToken> listRefreshTokens() {
      List<OAuth2RefreshToken> list = new LinkedList<>();
      for (TokenGroup tokens : refreshTokenMap.values()) {
        list.add(tokens.getRefreshToken());
      }
      return ImmutableList.copyOf(list);
    }

    public List<OAuth2AccessToken> listAccessTokens() {
      return ImmutableList.copyOf(accessTokenMap.values());
    }

    private static final class TokenGroup {
      private final OAuth2RefreshToken refreshToken;
      private Set<String> accessTokens = new HashSet<>();

      TokenGroup(OAuth2RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
      }

      public OAuth2RefreshToken getRefreshToken() {
        return refreshToken;
      }

      public Set<String> getAccessTokens() {
        return accessTokens;
      }
    }
  }
}
