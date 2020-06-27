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
import com.google.inject.Singleton;

import javax.crypto.KeyGenerator;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.UUID;
import java.util.Optional;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Default in memory token service.
 * An implementation of {@link OAuth2TokenService}.
 * The encryption of clientId and username is only needed in this InMemory Design.
 */
@Singleton
public class InMemoryOAuth2TokenService implements OAuth2TokenService {

    private static final Logger log = Logger.getLogger("InMemoryOAuth2TokenService");

    private long tokenValidTime = Duration.ofMinutes(10).getSeconds();

    Map<String, UserTokens> userTokensMap = new ConcurrentHashMap<>();

    private Key aesKey;

    ScheduledExecutorService service;

    public InMemoryOAuth2TokenService() {
        initKey();
        setTokenCleaner();
    }

    public InMemoryOAuth2TokenService(long tokenValidTime) {
        this.tokenValidTime = tokenValidTime;
        initKey();
        setTokenCleaner();
    }

    private void initKey() {
        KeyGenerator generator;
        try {
            generator = KeyGenerator.getInstance("AES");
            generator.init(256);
        } catch (NoSuchAlgorithmException e) {
            log.log(Level.INFO, "Error when init Key!",  e);
            return;
        }
        aesKey = generator.generateKey();
    }

    private class TokenCleaner implements Runnable {

        @Override
        public void run() {
            for (Map.Entry<String, UserTokens> user : userTokensMap.entrySet()) {
                user.getValue().clearExpiredTokens();
                if (user.getValue().isEmpty()) {
                    userTokensMap.remove(user.getKey());
                }
            }
        }
    }

    private void setTokenCleaner() {
        service = Executors.newSingleThreadScheduledExecutor();
        service.scheduleAtFixedRate(new TokenCleaner(), 1, 1, TimeUnit.HOURS);
    }

    public OAuth2AccessToken generateAccessToken(OAuth2Request request) {

        String clientID = request.getRequestAuth().getClientId();
        String username = request.getRequestAuth().getUsername();

        if (!userTokensMap.containsKey(username)) {
            userTokensMap.put(username, new UserTokens(username));
        }

        UserTokens user = userTokensMap.get(username);

        Optional<String> refreshTokenString = Optional.empty();

        if (request.getRequestBody().getRefreshable()) {
            // Merge all scopes
            if (request.getRequestBody().getIsScoped() &&
                    user.getRefreshToken(clientID).isPresent()) {
                OAuth2RefreshToken oldToken = user.getRefreshToken(clientID).get();
                OAuth2Request.Builder builder =
                        OAuth2Request.newBuilder(request);
                if (oldToken.getIsScoped()) {
                    HashSet<String> scopes =
                            new HashSet<>(request.getRequestBody().getScopesList());
                    scopes.addAll(oldToken.getScopesList());
                    builder.getRequestBodyBuilder().clearScopes().addAllScopes(scopes);
                } else {
                    builder.getRequestBodyBuilder().setIsScoped(false).clearScopes();
                }
                request = builder.build();
            }

            String refreshTokenValue = UUID.randomUUID().toString();
            refreshTokenString =
                    Optional.of(
                            new UserClientTokenInfo(username, clientID, refreshTokenValue)
                                    .getEncryptTokenString(aesKey));

            OAuth2RefreshToken refreshToken =
                    OAuth2RefreshToken.newBuilder()
                            .setRefreshToken(refreshTokenString.get())
                            .setClientId(request.getRequestAuth().getClientId())
                            .setUsername(request.getRequestAuth().getUsername())
                            .setIsScoped(request.getRequestBody().getIsScoped())
                            .addAllScopes(request.getRequestBody().getScopesList())
                            .build();

            user.setRefreshToken(clientID, refreshToken);
        }

        return getNewAccessToken(request, refreshTokenString);
    }

    public Optional<OAuth2AccessToken> refreshToken(String refreshToken) {
        Optional<OAuth2RefreshToken> token = readRefreshToken(refreshToken);

        if (!token.isPresent()) {
            return Optional.empty();
        }

        String username = token.get().getUsername();
        String clientID = token.get().getClientId();

        OAuth2Request.Builder requestBuilder = OAuth2Request.newBuilder();
        requestBuilder.getRequestAuthBuilder().setClientId(clientID).setUsername(username);
        requestBuilder.getRequestBodyBuilder()
                .setIsScoped(token.get().getIsScoped())
                .addAllScopes(token.get().getScopesList())
                .setRefreshable(true);

        return Optional.of(getNewAccessToken(requestBuilder.build(), Optional.of(refreshToken)));
    }

    private OAuth2AccessToken getNewAccessToken(
            OAuth2Request request, Optional<String> refreshTokenString){

        String clientID = request.getRequestAuth().getClientId();
        String username = request.getRequestAuth().getUsername();

        UserTokens user = userTokensMap.get(username);

        String accessTokenValue = UUID.randomUUID().toString();

        while (user.readAccessToken(clientID, accessTokenValue).isPresent()) {
            accessTokenValue = UUID.randomUUID().toString();
        }

        String accessTokenString =
                new UserClientTokenInfo(username, clientID, accessTokenValue)
                        .getEncryptTokenString(aesKey);

        OAuth2AccessToken.Builder builder =
                OAuth2AccessToken.newBuilder()
                        .setAccessToken(accessTokenString)
                        .setClientId(request.getRequestAuth().getClientId())
                        .setUsername(request.getRequestAuth().getUsername())
                        .setIsScoped(request.getRequestBody().getIsScoped())
                        .addAllScopes(request.getRequestBody().getScopesList())
                        .setExpiredTime(Instant.now().plusSeconds(tokenValidTime).getEpochSecond());
        refreshTokenString.ifPresent(builder::setRefreshToken);
        OAuth2AccessToken token = builder.build();
        user.addAccessToken(clientID, accessTokenValue, token);
        return token;
    }

    public Optional<OAuth2AccessToken> readAccessToken(String accessToken) {
        UserClientTokenInfo info;

        try{
            info = UserClientTokenInfo.decryptTokenString(aesKey, accessToken);
        } catch (InvalidParameterException exception) {
            log.log(Level.INFO,  "Invalid access token Value", exception);
            return Optional.empty();
        }

        String username = info.getUsername();
        String clientID = info.getClientID();
        String tokenValue = info.getTokenValue();

        if (userTokensMap.containsKey(username)) {
            return userTokensMap.get(username).readAccessToken(clientID, tokenValue);
        } else {
            return Optional.empty();
        }
    }

    public Optional<OAuth2RefreshToken> readRefreshToken(String refreshToken) {
        UserClientTokenInfo info;

        try{
            info = UserClientTokenInfo.decryptTokenString(aesKey, refreshToken);
        } catch (InvalidParameterException exception) {
            log.log(Level.INFO,  "Invalid refresh token Value", exception);
            return Optional.empty();
        }

        String username = info.getUsername();
        String clientID = info.getClientID();

        if (userTokensMap.containsKey(username)) {
            return userTokensMap.get(username).readRefreshToken(clientID, refreshToken);
        } else {
            return Optional.empty();
        }
    }

    public boolean revokeByAccessToken(String accessToken) {
        Optional<OAuth2AccessToken> token = readAccessToken(accessToken);

        if (!token.isPresent() ||
                Instant.ofEpochSecond(token.get().getExpiredTime()).isBefore(Instant.now())) {
            return false;
        }

        revokeUserClientTokens(token.get().getUsername(), token.get().getClientId());

        return true;
    }

    public boolean revokeByRefreshToken(String refreshToken) {
        Optional<OAuth2RefreshToken> token = readRefreshToken(refreshToken);

        if (!token.isPresent()) {
            return false;
        }

        revokeUserClientTokens(token.get().getUsername(), token.get().getClientId());

        return true;
    }

    public boolean revokeUserClientTokens(String username, String clientID){
        if (userTokensMap.containsKey(username)) {
            return userTokensMap.get(username).revokeUserClientTokens(clientID);
        } else {
            return false;
        }
    }

    public List<String> listUserClient(String username) {
        Set<String> clientList = new HashSet<>();

        if (userTokensMap.containsKey(username)) {
            return userTokensMap.get(username).listClients();
        } else {
            return ImmutableList.copyOf(clientList);
        }
    }

    public List<OAuth2AccessToken> listUserClientAccessTokens(String username, String clientID) {
        if (userTokensMap.containsKey(username)) {
            return userTokensMap.get(username).listAccessTokens(clientID);
        } else {
            return ImmutableList.of();
        }
    }

    public Optional<OAuth2RefreshToken> getUserClientRefreshToken(
            String username, String clientID) {
        if (userTokensMap.containsKey(username)) {
            return userTokensMap.get(username).getRefreshToken(clientID);
        } else {
            return Optional.empty();
        }
    }

}
