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

    Map<String, HashMap<String, HashMap<String, OAuth2RefreshToken>>> userClientRefreshTokenMap =
            new ConcurrentHashMap<>();

    private Key aesKey;

    ScheduledExecutorService service;

    public InMemoryOAuth2TokenService(){
        initKey();
        setTokenCleaner();
    }

    public InMemoryOAuth2TokenService(long tokenValidTime){
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

        UserClientTokenInfo(String username, String clientID, String tokenValue){
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
            String[] tokenInfo = tokenInfoString.split("\t");

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

        private void encryptTokenString(){
            String tokenInfo  = username + "\t" + clientID + "\t" + tokenValue;
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

        private String decryptTokenString(){
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
            for (HashMap<String, HashMap<String, OAuth2AccessToken>> userMap
                    : userClientAccessTokenMap.values()) {
                for (HashMap<String, OAuth2AccessToken> tokenMap : userMap.values()) {
                    for (OAuth2AccessToken token : tokenMap.values()){
                        if (token.getExpiredTime() < (new Date()).getTime()/1000l){
                            revokeAccessToken(token.getAccessToken());
                        }
                    }
                }
            }
        }
    };

    private void setTokenCleaner(){
        service = Executors.newSingleThreadScheduledExecutor();
        service.scheduleAtFixedRate(
                new TokenCleaner(), 60*60, 60*60, TimeUnit.SECONDS);
    }

    public OAuth2AccessToken generateAccessToken(OAuth2Request request) {
        String clientID = request.getRequestAuth().getClientId();
        String username = request.getRequestAuth().getUsername();

        if (!userClientAccessTokenMap.containsKey(username)) {
            userClientAccessTokenMap.put(username, new HashMap<>());
        }

        if (!userClientAccessTokenMap.get(username).containsKey(clientID)) {
            userClientAccessTokenMap.get(username).put(clientID, new HashMap<>());
        }

        HashMap<String, OAuth2AccessToken> accessTokenMap =
                userClientAccessTokenMap.get(username).get(clientID);

        String accessTokenValue = UUID.randomUUID().toString();

        while (accessTokenMap.containsKey(accessTokenValue)){
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
                        .setRefreshable(request.getRequestBody().getRefreshable());

        if (request.getRequestBody().getRefreshable()) {

            if (!userClientRefreshTokenMap.containsKey(username)) {
                userClientRefreshTokenMap.put(username, new HashMap<>());
            }

            if (!userClientRefreshTokenMap.get(username).containsKey(clientID)) {
                userClientRefreshTokenMap.get(username).put(clientID, new HashMap<>());
            }

            HashMap<String, OAuth2RefreshToken>  refreshTokenMap=
                    userClientRefreshTokenMap.get(username).get(clientID);

            String refreshTokenValue = UUID.randomUUID().toString();
            while (refreshTokenMap.containsKey(refreshTokenValue)) {
                refreshTokenValue = UUID.randomUUID().toString();
            }

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
            refreshTokenMap.put(refreshTokenValue, refreshToken);

            builder.setRefreshToken(refreshToken.getRefreshToken());
        }

        OAuth2AccessToken token =
                builder.setExpiredTime((new Date().getTime())/1000l + tokenValidTime).build();
        accessTokenMap.put(accessTokenValue, token);

        return token;
    }

    public Optional<OAuth2AccessToken> refreshToken(String refreshToken) {
        UserClientTokenInfo info = null;

        try{
            info = new UserClientTokenInfo(refreshToken);
        } catch (InvalidParameterException exception){
            log.log(Level.INFO,  "Invalid refresh token Value", exception);
            return Optional.empty();
        }

        String username = info.getUsername();
        String clientID = info.getClientID();
        String tokenValue = info.getTokenValue();

        if (userClientRefreshTokenMap.containsKey(username) &&
                userClientRefreshTokenMap.get(username).containsKey(clientID) &&
                userClientRefreshTokenMap.get(username).get(clientID).containsKey(tokenValue)) {

            OAuth2RefreshToken refreshTokenInfo =
                    userClientRefreshTokenMap.get(username).get(clientID).get(tokenValue);

            HashMap<String, OAuth2AccessToken>  accessTokenMap=
                    userClientAccessTokenMap.get(username).get(clientID);

            String accessTokenValue = UUID.randomUUID().toString();

            while (accessTokenMap.containsKey(accessTokenValue)){
                accessTokenValue = UUID.randomUUID().toString();
            }

            UserClientTokenInfo info1 =
                    new UserClientTokenInfo(username, clientID, accessTokenValue);

            OAuth2AccessToken newToken =
                    OAuth2AccessToken.newBuilder()
                            .setAccessToken(info.getTokenString())
                            .setClientId(clientID)
                            .setUsername(username)
                            .setIsScoped(refreshTokenInfo.getIsScoped())
                            .addAllScopes(refreshTokenInfo.getScopesList())
                            .setRefreshable(true)
                            .setRefreshToken(refreshToken)
                            .setExpiredTime((new Date().getTime())/1000l + tokenValidTime)
                            .build();

            accessTokenMap.put(accessTokenValue, newToken);

            return Optional.ofNullable(newToken);
        } else {
            return Optional.empty();
        }
    }

    public Optional<OAuth2AccessToken> readAccessToken(String accessToken) {
        UserClientTokenInfo info = null;

        try{
            info = new UserClientTokenInfo(accessToken);
        } catch (InvalidParameterException exception){
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
        } catch (InvalidParameterException exception){
            log.log(Level.INFO,  "Invalid refresh token Value", exception);
            return Optional.empty();
        }

        String username = info.getUsername();
        String clientID = info.getClientID();
        String tokenValue = info.getTokenValue();

        if (userClientRefreshTokenMap.containsKey(username) &&
                userClientRefreshTokenMap.get(username).containsKey(clientID)) {
            return Optional.ofNullable(
                    userClientRefreshTokenMap.get(username).get(clientID).get(tokenValue));
        } else {
            return Optional.empty();
        }
    }

    public boolean revokeAccessToken(String accessToken) {
        UserClientTokenInfo info = null;

        try{
            info = new UserClientTokenInfo(accessToken);
        } catch (InvalidParameterException exception){
            log.log(Level.INFO,  "Invalid refresh token Value", exception);
            return false;
        }

        String username = info.getUsername();
        String clientID = info.getClientID();
        String tokenValue = info.getTokenValue();

        if (userClientAccessTokenMap.containsKey(username) &&
                userClientAccessTokenMap.get(username).containsKey(clientID) &&
                userClientAccessTokenMap.get(username).get(clientID).containsKey(tokenValue)) {
            userClientAccessTokenMap.get(username).get(clientID).remove(tokenValue);
            return true;
        } else {
            return false;
        }
    }

    public boolean revokeRefreshToken(String refreshToken) {
        UserClientTokenInfo info = null;

        try{
            info = new UserClientTokenInfo(refreshToken);
        } catch (InvalidParameterException exception){
            log.log(Level.INFO,  "Invalid refresh token Value", exception);
            return false;
        }

        String username = info.getUsername();
        String clientID = info.getClientID();
        String tokenValue = info.getTokenValue();

        if (userClientRefreshTokenMap.containsKey(username) &&
                userClientRefreshTokenMap.get(username).containsKey(clientID) &&
                userClientRefreshTokenMap.get(username).get(clientID).containsKey(tokenValue)) {
            userClientRefreshTokenMap.get(username).get(clientID).remove(tokenValue);
            return true;
        } else {
            return false;
        }
    }

    public List<String> listUserClient(String username) {
        Set<String> clientList = new HashSet<>();
        if (userClientAccessTokenMap.containsKey(username)) {
            HashMap<String, HashMap<String, OAuth2AccessToken>> map =
                    userClientAccessTokenMap.get(username);
            for (Map.Entry<String, HashMap<String, OAuth2AccessToken>> entry : map.entrySet()) {
                if (!entry.getValue().isEmpty()) {
                    clientList.add(entry.getKey());
                }
            }
        }

        if (userClientRefreshTokenMap.containsKey(username)) {
            HashMap<String, HashMap<String, OAuth2RefreshToken>> map =
                    userClientRefreshTokenMap.get(username);
            for (Map.Entry<String, HashMap<String, OAuth2RefreshToken>> entry : map.entrySet()) {
                if (!entry.getValue().isEmpty()) {
                    clientList.add(entry.getKey());
                }
            }
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

    public List<OAuth2RefreshToken> listUserClientRefreshTokens(String username, String clientID) {
        if (userClientRefreshTokenMap.containsKey(username) &&
                userClientRefreshTokenMap.get(username).containsKey(clientID)) {
            return ImmutableList.copyOf(
                    userClientRefreshTokenMap.get(username).get(clientID).values());
        } else {
            return ImmutableList.of();
        }
    }

}
