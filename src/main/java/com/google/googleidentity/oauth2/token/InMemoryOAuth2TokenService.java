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
import com.google.common.io.BaseEncoding;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.inject.Singleton;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
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

    private long tokenValidTime = 10 * 60l;

    Map<String, HashMap<String, HashMap<String, OAuth2AccessToken>>> userClientAccessTokenMap =
            new ConcurrentHashMap<>();

    Map<String, HashMap<String, OAuth2RefreshToken>> userClientRefreshTokenMap =
            new ConcurrentHashMap<>();

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

    /**
     * Used for encrypt username and clientID
     */
    private class UserClientTokenInfo {
        private String username;
        private String clientID;
        private String tokenValue;
        private String tokenString;

        private String delimiter = "\t";

        UserClientTokenInfo(String username, String clientID, String tokenValue) {
            this.username = username;
            this.clientID = clientID;
            this.tokenValue = tokenValue;
            encryptTokenString();
        }

        UserClientTokenInfo(String tokenString) throws InvalidParameterException {
            this.tokenString = tokenString;
            String tokenInfoString = decryptTokenString();
            if (tokenInfoString == null) {
                throw new InvalidParameterException();
            }
            String[] tokenInfo = tokenInfoString.split(delimiter);

            if (tokenInfo.length != 3) {
                throw new InvalidParameterException();
            }

            username = tokenInfo[0];
            clientID = tokenInfo[1];
            tokenValue = tokenInfo[2];
        }

        public String getUsername() {
            return username;
        }

        public String getClientID() {
            return clientID;
        }

        public String getTokenValue() {
            return tokenValue;
        }

        public String getTokenString() {
            return tokenString;
        }

        private void encryptTokenString() {
            String tokenInfo  = username + delimiter + clientID + delimiter + tokenValue;
            try {
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] bytesToEncrypt = tokenInfo.getBytes("UTF-8");
                byte[] encryptedBytes = cipher.doFinal(bytesToEncrypt);
                tokenString = BaseEncoding.base64Url().encode(encryptedBytes);
            } catch (Exception e) {
                log.log(Level.INFO, "Error when encode tokenString!",  e);
            }
        }

        private String decryptTokenString() {
            try {
                Cipher cipher = Cipher.getInstance("AES");
                byte[] bytesToDecrypt = BaseEncoding.base64Url().decode(tokenString);
                cipher.init(Cipher.DECRYPT_MODE, aesKey);
                byte[] decryptedBytes = cipher.doFinal(bytesToDecrypt);
                return new String(decryptedBytes, "UTF-8");
            } catch (Exception e) {
                log.log(Level.INFO, "Error when encode tokenString!",  e);
                return null;
            }
        }

    }

    private void initKey() {
        KeyGenerator generator = null;
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
            for (Map.Entry<String, HashMap<String, HashMap<String, OAuth2AccessToken>>> userMap :
                    userClientAccessTokenMap.entrySet()) {
                for (Map.Entry<String, HashMap<String, OAuth2AccessToken>> tokenMap :
                        userMap.getValue().entrySet()) {
                    for (Map.Entry<String, OAuth2AccessToken> token :
                            tokenMap.getValue().entrySet()) {
                        if (token.getValue().getExpiredTime() < (new Date()).getTime()/1000l) {
                            tokenMap.getValue().remove(token.getKey());
                            if (tokenMap.getValue().isEmpty()) {
                                userMap.getValue().remove(tokenMap.getKey());
                                if (userMap.getValue().isEmpty()) {
                                    userClientAccessTokenMap.remove(userMap.getKey());
                                }
                            }
                        }
                    }
                }
            }
        }
    };

    private void setTokenCleaner() {
        service = Executors.newSingleThreadScheduledExecutor();
        service.scheduleAtFixedRate(
                new TokenCleaner(), 60*60, 60*60, TimeUnit.SECONDS);
    }

    public OAuth2AccessToken generateAccessToken(OAuth2Request request) {

        String clientID = request.getRequestAuth().getClientId();
        String username = request.getRequestAuth().getUsername();

        if (request.getRequestBody().getRefreshable()) {
            if (!userClientRefreshTokenMap.containsKey(username)) {
                 userClientRefreshTokenMap.put(username, new HashMap<>());
            }

            HashMap<String, OAuth2RefreshToken>  refreshTokenMap=
                    userClientRefreshTokenMap.get(username);

            // Merge all scopes
            if (request.getRequestBody().getIsScoped() && refreshTokenMap.containsKey(clientID)) {
                OAuth2RefreshToken oldToken = refreshTokenMap.get(clientID);
                OAuth2Request.Builder builder =
                        OAuth2Request.newBuilder(request);
                if (!oldToken.getIsScoped()) {
                    builder.getRequestBodyBuilder().setIsScoped(false).clearScopes();
                    request = builder.build();
                } else {
                    HashSet<String> scopes =
                            new HashSet<>(request.getRequestBody().getScopesList());
                    scopes.addAll(oldToken.getScopesList());
                    builder.getRequestBodyBuilder().clearScopes().addAllScopes(scopes);
                    request = builder.build();
                }
            }
        }

        if (!userClientAccessTokenMap.containsKey(username)) {
            userClientAccessTokenMap.put(username, new HashMap<>());
        }

        if (!userClientAccessTokenMap.get(username).containsKey(clientID)) {
            userClientAccessTokenMap.get(username).put(clientID, new HashMap<>());
        }

        HashMap<String, OAuth2AccessToken> accessTokenMap =
                userClientAccessTokenMap.get(username).get(clientID);

        String accessTokenValue = UUID.randomUUID().toString();

        while (accessTokenMap.containsKey(accessTokenValue)) {
            accessTokenValue = UUID.randomUUID().toString();
        }

        UserClientTokenInfo info = new UserClientTokenInfo(username, clientID, accessTokenValue);

        OAuth2AccessToken.Builder builder =
                OAuth2AccessToken.newBuilder()
                        .setAccessToken(info.getTokenString())
                        .setClientId(request.getRequestAuth().getClientId())
                        .setUsername(request.getRequestAuth().getUsername())
                        .setIsScoped(request.getRequestBody().getIsScoped())
                        .addAllScopes(request.getRequestBody().getScopesList())
                        .setExpiredTime((new Date().getTime())/1000l + tokenValidTime);

        if (request.getRequestBody().getRefreshable()) {
            String refreshTokenValue = UUID.randomUUID().toString();
            UserClientTokenInfo info1 =
                    new UserClientTokenInfo(username, clientID, refreshTokenValue);

            OAuth2RefreshToken refreshToken =
                    OAuth2RefreshToken.newBuilder()
                            .setRefreshToken(info1.getTokenString())
                            .setClientId(request.getRequestAuth().getClientId())
                            .setUsername(request.getRequestAuth().getUsername())
                            .setIsScoped(request.getRequestBody().getIsScoped())
                            .addAllScopes(request.getRequestBody().getScopesList())
                            .build();

            userClientRefreshTokenMap.get(username).put(clientID, refreshToken);

            builder.setRefreshToken(refreshToken.getRefreshToken());
        }

        OAuth2AccessToken token = builder.build();

        accessTokenMap.put(accessTokenValue, token);
        return token;
    }

    public Optional<OAuth2AccessToken> refreshToken(String refreshToken) {
        Optional<OAuth2RefreshToken> token = readRefreshToken(refreshToken);

        if (!token.isPresent()) {
            return Optional.empty();
        }

        String username = token.get().getUsername();
        String clientID = token.get().getClientId();

        HashMap<String, OAuth2AccessToken>  accessTokenMap=
                    userClientAccessTokenMap.get(username).get(clientID);

        String accessTokenValue = UUID.randomUUID().toString();

        while (accessTokenMap.containsKey(accessTokenValue)) {
            accessTokenValue = UUID.randomUUID().toString();
        }

        UserClientTokenInfo info =
                new UserClientTokenInfo(username, clientID, accessTokenValue);

        OAuth2AccessToken newToken =
                OAuth2AccessToken.newBuilder()
                        .setAccessToken(info.getTokenString())
                        .setClientId(clientID)
                        .setUsername(username)
                        .setIsScoped(token.get().getIsScoped())
                        .addAllScopes(token.get().getScopesList())
                        .setExpiredTime((new Date().getTime())/1000l + tokenValidTime)
                        .setRefreshToken(refreshToken)
                        .build();

        accessTokenMap.put(accessTokenValue, newToken);

        return Optional.ofNullable(newToken);
    }

    public Optional<OAuth2AccessToken> readAccessToken(String accessToken) {
        UserClientTokenInfo info = null;

        try{
            info = new UserClientTokenInfo(accessToken);
        } catch (InvalidParameterException exception) {
            log.log(Level.INFO,  "Invalid refresh token Value", exception);
            return Optional.empty();
        }

        String username = info.getUsername();
        String clientID = info.getClientID();
        String tokenValue = info.getTokenValue();

        if (userClientAccessTokenMap.containsKey(username) &&
                userClientAccessTokenMap.get(username).containsKey(clientID)) {
            return Optional.ofNullable(
                    userClientAccessTokenMap.get(username).get(clientID).get(tokenValue));
        } else {
            return Optional.empty();
        }
    }

    public Optional<OAuth2RefreshToken> readRefreshToken(String refreshToken) {
        UserClientTokenInfo info = null;

        try{
            info = new UserClientTokenInfo(refreshToken);
        } catch (InvalidParameterException exception) {
            log.log(Level.INFO,  "Invalid refresh token Value", exception);
            return Optional.empty();
        }

        String username = info.getUsername();
        String clientID = info.getClientID();
        String tokenValue = info.getTokenValue();

        if (userClientRefreshTokenMap.containsKey(username) &&
                userClientRefreshTokenMap.get(username).containsKey(clientID)) {
            OAuth2RefreshToken token = userClientRefreshTokenMap.get(username).get(clientID);
            if (token.getRefreshToken().equals(refreshToken)) {
                return Optional.ofNullable(token);
            } else {
                return Optional.empty();
            }
        } else {
            return Optional.empty();
        }
    }

    public boolean revokeByAccessToken(String accessToken) {
        Optional<OAuth2AccessToken> token = readAccessToken(accessToken);

        if (!token.isPresent() || token.get().getExpiredTime() < (new Date()).getTime()/1000l) {
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

    public void revokeUserClientTokens(String username, String clientID){
        if (userClientAccessTokenMap.containsKey(username)
            && userClientAccessTokenMap.get(username).containsKey(clientID)) {
            userClientAccessTokenMap.get(username).remove(clientID);
            if (userClientAccessTokenMap.get(username).isEmpty()) {
                userClientAccessTokenMap.remove(username);
            }
        }

        if (userClientRefreshTokenMap.containsKey(username)
                && userClientRefreshTokenMap.get(username).containsKey(clientID)) {
            userClientRefreshTokenMap.get(username).remove(clientID);
            if (userClientRefreshTokenMap.get(username).isEmpty()) {
                userClientRefreshTokenMap.remove(username);
            }
        }
    }

    public List<String> listUserClient(String username) {
        Set<String> clientList = new HashSet<>();

        if (userClientAccessTokenMap.containsKey(username)) {
            clientList.addAll(userClientAccessTokenMap.get(username).keySet());
        }

        // For authorization code grant type, since access tokens may
        // be out of date and be cleared, we have to check refresh token
        if (userClientRefreshTokenMap.containsKey(username)) {
            clientList.addAll(userClientRefreshTokenMap.get(username).keySet());
        }

        return ImmutableList.copyOf(clientList);
    }

    public List<OAuth2AccessToken> listUserClientAccessTokens(String username, String clientID) {
        if (userClientAccessTokenMap.containsKey(username) &&
                userClientAccessTokenMap.get(username).containsKey(clientID)) {
                return ImmutableList.copyOf(
                        userClientAccessTokenMap.get(username).get(clientID).values());
        } else {
            return ImmutableList.of();
        }
    }

    public Optional<OAuth2RefreshToken> getUserClientRefreshToken(
            String username, String clientID) {
        if (userClientRefreshTokenMap.containsKey(username)) {
            return Optional.ofNullable(userClientRefreshTokenMap.get(username).get(clientID));
        } else {
            return Optional.empty();
        }
    }

}
