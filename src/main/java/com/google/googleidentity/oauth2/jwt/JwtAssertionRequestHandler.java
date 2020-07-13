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

package com.google.googleidentity.oauth2.jwt;

import com.google.common.collect.ImmutableList;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.InvalidRequestException.ErrorCode;
import com.google.googleidentity.oauth2.exception.InvalidScopeException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.request.RequestHandler;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;
import org.apache.http.HttpStatus;

/** Processor for dealing JWT Assertion */
@Singleton
public class JwtAssertionRequestHandler implements RequestHandler {

  private static final String keyUrl = "https://www.googleapis.com/oauth2/v3/certs";
  private static final String aud =
      "475640046628-i42g5qfbcp58e3nijqiedomvhe7hb3sn.apps.googleusercontent.com";
  private final OAuth2TokenService oauth2TokenService;
  private final UserDetailsService userDetailsService;

  private final ClientDetailsService clientDetailsService;

  private final Logger log = Logger.getLogger("JwtAssertionTokenProcessor");

  @Inject
  public JwtAssertionRequestHandler(
      OAuth2TokenService oauth2TokenService,
      UserDetailsService userDetailsService,
      ClientDetailsService clientDetailsService) {
    this.oauth2TokenService = oauth2TokenService;
    this.userDetailsService = userDetailsService;
    this.clientDetailsService = clientDetailsService;
  }

  @Override
  public void handle(HttpServletResponse response, OAuth2Request oauth2Request)
      throws IOException, OAuth2Exception {
    List<String> info =
        verifyAndGetInfoFromJwt(
            oauth2Request.getRequestBody().getAssertion(), new JwtSigningKeyResolver(keyUrl));
    String email = info.get(0);
    String googleAccountId = info.get(1);
    switch (oauth2Request.getRequestBody().getIntent()) {
      case CHECK:
        handleCheckAssertion(response, email, googleAccountId);
        break;
      case GET:
        handleGetAssertion(
            response, email, googleAccountId, oauth2Request.getRequestBody().getScopesList());
        break;
      case CREATE:
        handleCreateAssertion(
            response, email, googleAccountId, oauth2Request.getRequestBody().getScopesList());
        break;
      default:
        throw new IllegalStateException();
    }
  }

  public List<String> verifyAndGetInfoFromJwt(String assertion, SigningKeyResolverAdapter keys)
      throws OAuth2Exception {
    Jws<Claims> jws;

    String email = null;
    String googleAccountId = null;
    try {
      jws = Jwts.parserBuilder().setSigningKeyResolver(keys).build().parseClaimsJws(assertion);
      if (!jws.getBody().getIssuer().equals("https://accounts.google.com")) {
        throw new InvalidRequestException(ErrorCode.INVALID_JWT_ISS);
      }
      if (!jws.getBody().getAudience().equals(aud)) {
        throw new InvalidRequestException(ErrorCode.WRONG_JWT_AUD);
      }
      email = jws.getBody().get("email", String.class);
      googleAccountId = jws.getBody().get("sub", Long.class).toString();
    } catch (JwtException ex) {
      log.log(Level.INFO, "JWT Decode ERROR!", ex);
      throw new InvalidRequestException(ErrorCode.INVALID_JWT);
    }
    return ImmutableList.of(email, googleAccountId);
  }

  public void handleCheckAssertion(
      HttpServletResponse response, String email, String googleAccountId) throws IOException {
    Optional<UserDetails> user =
        userDetailsService.getUserByEmailOrGoogleAccountId(email, googleAccountId);
    JSONObject json = new JSONObject();
    if (user.isPresent()) {
      json.appendField("account_found", "true");
      response.setContentType("application/json;charset=UTF-8");
      response.getWriter().println(json.toJSONString());
    } else {
      json.appendField("account_found", "false");
      response.setContentType("application/json;charset=UTF-8");
      response.getWriter().println(json.toJSONString());
      response.setStatus(HttpStatus.SC_NOT_FOUND);
    }
    response.getWriter().flush();
  }

  public void handleGetAssertion(
      HttpServletResponse response, String email, String googleAccountId, List<String> scopes)
      throws IOException, InvalidScopeException {
    Optional<UserDetails> user =
        userDetailsService.getUserByEmailOrGoogleAccountId(email, googleAccountId);
    if (user.isPresent()) {
      ClientDetails client = clientDetailsService.getClientByID("google").get();

      if (!scopes.isEmpty()
          && client.getIsScoped()
          && !client.getScopesList().containsAll(scopes)) {
        throw new InvalidScopeException();
      }

      if (scopes.isEmpty() && client.getIsScoped()) {
        scopes = client.getScopesList();
      }
      returnToken(response, client, user.get(), scopes);

    } else {
      returnLinkError(response, email);
    }
  }

  public void handleCreateAssertion(
      HttpServletResponse response, String email, String googleAccountId, List<String> scopes)
      throws IOException, InvalidScopeException {
    Optional<UserDetails> user =
        userDetailsService.getUserByEmailOrGoogleAccountId(email, googleAccountId);
    if (user.isPresent()) {
      returnLinkError(response, email);
    } else {
      UserDetails newUser =
          UserDetails.newBuilder()
              .setUsername("GAL:" + email)
              .setEmail(email)
              .setGoogleAccountId(googleAccountId)
              .build();
      userDetailsService.addUser(newUser);
      ClientDetails client = clientDetailsService.getClientByID("google").get();
      if (!scopes.isEmpty()
          && client.getIsScoped()
          && (!client.getScopesList().containsAll(scopes))) {
        throw new InvalidScopeException();
      }

      if (scopes.isEmpty() && client.getIsScoped()) {
        scopes = client.getScopesList();
      }
      returnToken(response, client, newUser, scopes);
    }
  }

  private void returnToken(
      HttpServletResponse response, ClientDetails client, UserDetails user, List<String> scopes)
      throws IOException {
    OAuth2Request.Builder tokenRequestBuilder = OAuth2Request.newBuilder();
    tokenRequestBuilder
        .getRequestAuthBuilder()
        .setClientId(client.getClientId())
        .setUsername(user.getUsername());
    tokenRequestBuilder
        .getRequestBodyBuilder()
        .setIsScoped(client.getIsScoped())
        .addAllScopes(scopes)
        .setRefreshable(true);
    OAuth2AccessToken token = oauth2TokenService.generateAccessToken(tokenRequestBuilder.build());
    JSONObject json = new JSONObject();

    json.appendField("token_type", "Bearer");
    json.appendField(OAuth2ParameterNames.ACCESS_TOKEN, token.getAccessToken());
    json.appendField(OAuth2ParameterNames.REFRESH_TOKEN, token.getRefreshToken());
    json.appendField("expires_in", token.getExpiredTime() - Instant.now().getEpochSecond());

    response.setContentType("application/json");

    response.getWriter().println(json.toJSONString());

    response.getWriter().flush();
  }

  private void returnLinkError(HttpServletResponse response, String email) throws IOException {
    JSONObject json = new JSONObject();
    json.appendField("error", "linking_error");
    json.appendField("login_hint", email);
    response.setContentType("application/json;charset=UTF-8");
    response.getWriter().println(json.toJSONString());
    response.setStatus(HttpStatus.SC_UNAUTHORIZED);
  }
}
