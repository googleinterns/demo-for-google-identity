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

package com.google.googleidentity.oauth2.risc;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.OAuth2ServerException;
import com.google.googleidentity.oauth2.jwt.JwkStore;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2RefreshToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Constants.TokenTypes;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.StandardCharset;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.EntityBuilder;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

/** Revoke tokens between a user and a client. Send risc if the client support it. */
@Singleton
public class RiscHandler {
  private static final Logger log = Logger.getLogger("RiscHandler");
  private static int MAX_RETRY_COUNT = 4;
  private static Duration RETRY_INTERVAL_TIME = Duration.ofMinutes(10);
  private static String WEB_URL =
      System.getenv("WEB_URL") == null ? "localhost:8080" : System.getenv("WEB_URL");
  private final ClientDetailsService clientDetailsService;
  private final JwkStore jwkStore;
  private long jtiValue = 0l;

  @Inject
  public RiscHandler(JwkStore jwkStore, ClientDetailsService clientDetailsService) {
    this.jwkStore = jwkStore;
    this.clientDetailsService = clientDetailsService;
  }

  public void SendRisc(
      List<OAuth2AccessToken> accessTokenList, List<OAuth2RefreshToken> refreshTokenList) {

    for (OAuth2AccessToken token : accessTokenList) {
      Thread thread = new sendEventThread(token);
      thread.start();
    }

    for (OAuth2RefreshToken token : refreshTokenList) {
      Thread thread = new sendEventThread(token);
      thread.start();
    }
  }

  private String getJtiValue(String clientID, String username) {
    return Hashing.sha512()
        .hashString(
            clientID + username + Instant.now().toString() + UUID.randomUUID().toString(),
            StandardCharset.UTF_8)
        .toString();
  }

  private class sendEventThread extends Thread {
    String tokenType;
    private OAuth2AccessToken accessToken;
    private OAuth2RefreshToken refreshToken;

    sendEventThread(OAuth2AccessToken oauth2AccessToken) {
      this.accessToken = oauth2AccessToken;
      tokenType = TokenTypes.ACCESS_TOKEN;
    }

    sendEventThread(OAuth2RefreshToken oauth2RefreshToken) {
      this.refreshToken = oauth2RefreshToken;
      tokenType = TokenTypes.REFRESH_TOKEN;
    }

    public void run() {
      boolean successfullySentEvent = false;
      int sendCount = 0;
      JWK jwk = jwkStore.getJWK();
      Key key = null;
      try {
        key = jwk.toRSAKey().toPrivateKey();
      } catch (JOSEException exception) {
        log.log(Level.INFO, "jwk error", exception);
      }

      Map<String, Object> claims = new HashMap<String, Object>();

      Map<String, Object> events = new HashMap<String, Object>();

      events.put("subject_type", "oauth_token");
      events.put("token_type", tokenType);
      events.put("token_identifier_alg", "hash_SHA512_double");

      String tokenValue =
          tokenType.equals(TokenTypes.ACCESS_TOKEN)
              ? accessToken.getAccessToken()
              : refreshToken.getRefreshToken();
      byte[] hash = Hashing.sha512().hashString(tokenValue, StandardCharset.UTF_8).asBytes();
      events.put("token", Hashing.sha512().hashBytes(hash).toString());

      String jtiValue =
          tokenType.equals(TokenTypes.ACCESS_TOKEN)
              ? getJtiValue(accessToken.getClientId(), accessToken.getUsername())
              : getJtiValue(refreshToken.getClientId(), refreshToken.getUsername());

      claims.put("https://schemas.openid.net/secevent/oauth/event-type/token-revoked", events);

      Optional<ClientDetails> client =
          clientDetailsService.getClientByID(accessToken.getClientId());

      Preconditions.checkArgument(
          clientDetailsService.getClientByID(accessToken.getClientId()).isPresent(),
          "Client should exist");

      while (!successfullySentEvent && sendCount < MAX_RETRY_COUNT) {
        sendCount++;
        String jws =
            Jwts.builder()
                .setIssuer(WEB_URL + "/oauth2/risc")
                .setAudience(client.get().getRiscAud())
                .setIssuedAt(Date.from(Instant.now()))
                .setId(jtiValue)
                .claim("events", claims)
                .signWith(key)
                .setHeaderParam("kid", jwk.getKeyID())
                .compact();

        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost httppost = new HttpPost(client.get().getRiscUri());
        httppost.setHeader("Content-Type", "application/secevent+jwt");
        httppost.setHeader("Accept", "application/json");
        httppost.setEntity(EntityBuilder.create().setText(jws).build());
        try {
          CloseableHttpResponse response = httpClient.execute(httppost);
          int status = response.getStatusLine().getStatusCode();
          successfullySentEvent = status == HttpStatus.SC_ACCEPTED;
        } catch (IOException exception) {
          throw new OAuth2ServerException("Send risc error!", exception);
        }
        try {
          Thread.sleep(RETRY_INTERVAL_TIME.toMillis());
        } catch (InterruptedException e) {
          throw new OAuth2ServerException("Thread sleep error when sending risc!", e);
        }
      }
    }
  }
}
