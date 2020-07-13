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

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.token.InMemoryOAuth2TokenService;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2RefreshToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.testtools.TestJwtSigningKeyResolver;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import javax.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;

public class JwtAssertionHandlerTest {
  private static final String CLIENTID = "google";
  private static final String SECRET = "secret";
  private static final String REDIRECT_URI = "http://www.google.com";
  private static final ClientDetails CLIENT =
      ClientDetails.newBuilder()
          .setClientId(CLIENTID)
          .setSecret(Hashing.sha256().hashString(SECRET, Charsets.UTF_8).toString())
          .addScopes("read")
          .setIsScoped(true)
          .addRedirectUris(REDIRECT_URI)
          .addGrantTypes(GrantType.AUTHORIZATION_CODE)
          .build();
  private static final String USERNAME = "usernames";
  private static final String PASSWORD = "password";
  private static final UserDetails USER =
      UserDetails.newBuilder()
          .setUsername(USERNAME)
          .setPassword(Hashing.sha256().hashString(PASSWORD, Charsets.UTF_8).toString())
          .setEmail("a@gmail.com")
          .build();

  private static final OAuth2Request TEST_REQUEST =
      OAuth2Request.newBuilder()
          .setRequestAuth(
              OAuth2Request.RequestAuth.newBuilder()
                  .setClientId(CLIENTID)
                  .setUsername(USERNAME)
                  .build())
          .setRequestBody(
              OAuth2Request.RequestBody.newBuilder()
                  .setIsScoped(true)
                  .addAllScopes(CLIENT.getScopesList())
                  .setGrantType(GrantType.JWT_ASSERTION)
                  .build())
          .build();

  OAuth2TokenService oauth2TokenService;
  JwtAssertionRequestHandler jwtAssertionRequestHandler;
  JwkStore jwkStore;

  @Before
  public void init() throws JOSEException {
    oauth2TokenService = new InMemoryOAuth2TokenService();
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
    clientDetailsService.addClient(CLIENT);
    UserDetailsService userDetailsService = new InMemoryUserDetailsService();
    userDetailsService.addUser(USER);
    jwkStore = new JwkStore();
    jwtAssertionRequestHandler =
        new JwtAssertionRequestHandler(
            oauth2TokenService, userDetailsService, clientDetailsService);
  }

  @Test
  public void testDecode_ExpiredJwt_throwInvalidRequestException()
      throws JOSEException, OAuth2Exception {
    HttpServletResponse response = mock(HttpServletResponse.class);

    JWK jwk = jwkStore.getJWK();
    Key key = jwk.toRSAKey().toPrivateKey();

    String assertion =
        Jwts.builder()
            .setIssuer("https://accounts.google.com")
            .setAudience("475640046628-i42g5qfbcp58e3nijqiedomvhe7hb3sn.apps.googleusercontent.com")
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now()))
            .claim("name", "a bc")
            .claim("given_name", "a")
            .claim("family_name", "bc")
            .claim("email", "a@gmail.com")
            .claim("email_verified", true)
            .claim("sub", 1234567890)
            .setHeaderParam("kid", jwk.getKeyID())
            .signWith(key)
            .compact();

    OAuth2Exception e =
        assertThrows(
            OAuth2Exception.class,
            () ->
                jwtAssertionRequestHandler.verifyAndGetInfoFromJwt(
                    assertion, new TestJwtSigningKeyResolver(jwkStore.getJWKString())));

    assertThat(e).isInstanceOf(InvalidRequestException.class);

    assertThat(e.getErrorDescription()).isEqualTo("Invalid jwt!");
  }

  @Test
  public void testDecode_WrongIss_throwInvalidRequestException()
      throws JOSEException, OAuth2Exception {
    HttpServletResponse response = mock(HttpServletResponse.class);

    JWK jwk = jwkStore.getJWK();
    Key key = jwk.toRSAKey().toPrivateKey();

    String assertion =
        Jwts.builder()
            .setIssuer("https://accounts.not.google.com")
            .setAudience("475640046628-i42g5qfbcp58e3nijqiedomvhe7hb3sn.apps.googleusercontent.com")
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plusSeconds(600)))
            .claim("name", "a bc")
            .claim("given_name", "a")
            .claim("family_name", "bc")
            .claim("email", "a@gmail.com")
            .claim("email_verified", true)
            .claim("sub", 1234567890)
            .setHeaderParam("kid", jwk.getKeyID())
            .signWith(key)
            .compact();

    OAuth2Exception e =
        assertThrows(
            OAuth2Exception.class,
            () ->
                jwtAssertionRequestHandler.verifyAndGetInfoFromJwt(
                    assertion, new TestJwtSigningKeyResolver(jwkStore.getJWKString())));

    assertThat(e).isInstanceOf(InvalidRequestException.class);

    assertThat(e.getErrorDescription()).isEqualTo("Invalid jwt iss!");
  }

  @Test
  public void testDecode_WrongAud_throwInvalidRequestException()
      throws JOSEException, OAuth2Exception {
    HttpServletResponse response = mock(HttpServletResponse.class);

    JWK jwk = jwkStore.getJWK();
    Key key = jwk.toRSAKey().toPrivateKey();

    String assertion =
        Jwts.builder()
            .setIssuer("https://accounts.google.com")
            .setAudience("not.my.service")
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plusSeconds(600)))
            .claim("name", "a bc")
            .claim("given_name", "a")
            .claim("family_name", "bc")
            .claim("email", "a@gmail.com")
            .claim("email_verified", true)
            .claim("sub", 1234567890)
            .setHeaderParam("kid", jwk.getKeyID())
            .signWith(key)
            .compact();

    OAuth2Exception e =
        assertThrows(
            OAuth2Exception.class,
            () ->
                jwtAssertionRequestHandler.verifyAndGetInfoFromJwt(
                    assertion, new TestJwtSigningKeyResolver(jwkStore.getJWKString())));

    assertThat(e).isInstanceOf(InvalidRequestException.class);

    assertThat(e.getErrorDescription()).isEqualTo("Wrong jwt aud!");
  }

  @Test
  public void testDecode_CorrectAssertion_CorrectEmailAndAccountId()
      throws JOSEException, OAuth2Exception {
    HttpServletResponse response = mock(HttpServletResponse.class);

    JWK jwk = jwkStore.getJWK();
    Key key = jwk.toRSAKey().toPrivateKey();

    String assertion =
        Jwts.builder()
            .setIssuer("https://accounts.google.com")
            .setAudience("475640046628-i42g5qfbcp58e3nijqiedomvhe7hb3sn.apps.googleusercontent.com")
            .setIssuedAt(Date.from(Instant.now()))
            .setExpiration(Date.from(Instant.now().plusSeconds(600)))
            .claim("name", "a bc")
            .claim("given_name", "a")
            .claim("family_name", "bc")
            .claim("email", "a@gmail.com")
            .claim("email_verified", true)
            .claim("sub", 1234567890)
            .setHeaderParam("kid", jwk.getKeyID())
            .signWith(key)
            .compact();

    assertDoesNotThrow(
        () ->
            jwtAssertionRequestHandler.verifyAndGetInfoFromJwt(
                assertion, new TestJwtSigningKeyResolver(jwkStore.getJWKString())));

    Pair<String, String> info =
        jwtAssertionRequestHandler.verifyAndGetInfoFromJwt(
            assertion, new TestJwtSigningKeyResolver(jwkStore.getJWKString()));
    assertThat(info.getLeft()).isEqualTo("a@gmail.com");
    assertThat(info.getRight()).isEqualTo("1234567890");
  }

  @Test
  public void testHandleCheck_userDoesNotExist_returnAccountFoundFalse()
      throws JOSEException, OAuth2Exception, IOException, ParseException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    assertDoesNotThrow(
        () ->
            jwtAssertionRequestHandler.handleCheckAssertion(response, "b@gmail.com", "1234567890"));

    JSONObject json =
        (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(stringWriter.toString());

    assertThat(json).containsEntry("account_found", "false");
  }

  @Test
  public void testHandleCheck_userExists_returnAccountFoundTrue()
      throws JOSEException, OAuth2Exception, IOException, ParseException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    assertDoesNotThrow(
        () ->
            jwtAssertionRequestHandler.handleCheckAssertion(response, "a@gmail.com", "1234567890"));

    JSONObject json =
        (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(stringWriter.toString());

    assertThat(json).containsEntry("account_found", "true");
  }

  @Test
  public void testHandleGet_userDoesNotExist_returnLinkError()
      throws JOSEException, OAuth2Exception, IOException, ParseException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    assertDoesNotThrow(
        () ->
            jwtAssertionRequestHandler.handleGetAssertion(
                response, "b@gmail.com", "1234567890", CLIENT.getScopesList(), CLIENT));

    JSONObject json =
        (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(stringWriter.toString());

    verify(response).setStatus(HttpStatus.SC_UNAUTHORIZED);

    assertThat(json).containsEntry("error", "linking_error");
    assertThat(json).containsEntry("login_hint", "b@gmail.com");
  }

  @Test
  public void testHandleGet_userExists_returnToken()
      throws JOSEException, OAuth2Exception, IOException, ParseException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    assertDoesNotThrow(
        () ->
            jwtAssertionRequestHandler.handleGetAssertion(
                response, "a@gmail.com", "1234567890", CLIENT.getScopesList(), CLIENT));

    JSONObject json =
        (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(stringWriter.toString());

    assertThat(json).containsKey(OAuth2ParameterNames.ACCESS_TOKEN);
    assertThat(json).containsKey(OAuth2ParameterNames.REFRESH_TOKEN);
    assertThat(json).containsKey("expires_in");
    assertThat(json).containsEntry("token_type", "Bearer");

    String accessTokenString = json.getAsString(OAuth2ParameterNames.ACCESS_TOKEN);
    String refreshTokenString = json.getAsString(OAuth2ParameterNames.REFRESH_TOKEN);

    OAuth2AccessToken expectedAccessToken =
        OAuth2AccessToken.newBuilder()
            .setAccessToken(accessTokenString)
            .setRefreshToken(refreshTokenString)
            .setIsScoped(true)
            .addAllScopes(CLIENT.getScopesList())
            .setClientId(CLIENTID)
            .setUsername(USERNAME)
            .build();
    Optional<OAuth2AccessToken> accessToken = oauth2TokenService.readAccessToken(accessTokenString);

    assertThat(accessToken).isPresent();

    assertThat(accessToken.get()).comparingExpectedFieldsOnly().isEqualTo(expectedAccessToken);

    OAuth2RefreshToken expectedRefreshToken =
        OAuth2RefreshToken.newBuilder()
            .setRefreshToken(refreshTokenString)
            .setClientId(CLIENTID)
            .setUsername(USERNAME)
            .setIsScoped(CLIENT.getIsScoped())
            .addAllScopes(CLIENT.getScopesList())
            .build();
    Optional<OAuth2RefreshToken> refreshToken =
        oauth2TokenService.readRefreshToken(refreshTokenString);

    assertThat(refreshToken).isPresent();

    assertThat(refreshToken.get()).comparingExpectedFieldsOnly().isEqualTo(expectedRefreshToken);
  }

  @Test
  public void testHandleCreate_userDoesNotExist_returnToken()
      throws JOSEException, OAuth2Exception, IOException, ParseException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    assertDoesNotThrow(
        () ->
            jwtAssertionRequestHandler.handleCreateAssertion(
                response, "b@gmail.com", "1234567890", CLIENT.getScopesList(), CLIENT));

    JSONObject json =
        (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(stringWriter.toString());

    assertThat(json).containsKey(OAuth2ParameterNames.ACCESS_TOKEN);
    assertThat(json).containsKey(OAuth2ParameterNames.REFRESH_TOKEN);
    assertThat(json).containsKey("expires_in");
    assertThat(json).containsEntry("token_type", "Bearer");

    String accessTokenString = json.getAsString(OAuth2ParameterNames.ACCESS_TOKEN);
    String refreshTokenString = json.getAsString(OAuth2ParameterNames.REFRESH_TOKEN);

    OAuth2AccessToken expectedAccessToken =
        OAuth2AccessToken.newBuilder()
            .setAccessToken(accessTokenString)
            .setRefreshToken(refreshTokenString)
            .setIsScoped(true)
            .addAllScopes(CLIENT.getScopesList())
            .setClientId(CLIENTID)
            .setUsername("GAL:b@gmail.com")
            .build();
    Optional<OAuth2AccessToken> accessToken = oauth2TokenService.readAccessToken(accessTokenString);

    assertThat(accessToken).isPresent();

    assertThat(accessToken.get()).comparingExpectedFieldsOnly().isEqualTo(expectedAccessToken);

    OAuth2RefreshToken expectedRefreshToken =
        OAuth2RefreshToken.newBuilder()
            .setRefreshToken(refreshTokenString)
            .setClientId(CLIENTID)
            .setUsername("GAL:b@gmail.com")
            .setIsScoped(CLIENT.getIsScoped())
            .addAllScopes(CLIENT.getScopesList())
            .build();
    Optional<OAuth2RefreshToken> refreshToken =
        oauth2TokenService.readRefreshToken(refreshTokenString);

    assertThat(refreshToken).isPresent();

    assertThat(refreshToken.get()).comparingExpectedFieldsOnly().isEqualTo(expectedRefreshToken);
  }

  @Test
  public void testHandleCreate_userExists_returnLinkError()
      throws JOSEException, OAuth2Exception, IOException, ParseException {
    HttpServletResponse response = mock(HttpServletResponse.class);

    StringWriter stringWriter = new StringWriter();
    PrintWriter writer = new PrintWriter(stringWriter);
    when(response.getWriter()).thenReturn(writer);

    assertDoesNotThrow(
        () ->
            jwtAssertionRequestHandler.handleCreateAssertion(
                response, "a@gmail.com", "1234567890", CLIENT.getScopesList(), CLIENT));

    JSONObject json =
        (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(stringWriter.toString());

    verify(response).setStatus(HttpStatus.SC_UNAUTHORIZED);

    assertThat(json).containsEntry("error", "linking_error");
    assertThat(json).containsEntry("login_hint", "a@gmail.com");
  }
}
