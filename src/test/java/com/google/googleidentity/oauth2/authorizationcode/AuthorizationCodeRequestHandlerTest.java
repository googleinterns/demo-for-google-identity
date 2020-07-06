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

package com.google.googleidentity.oauth2.authorizationcode;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidGrantException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.token.InMemoryOAuth2TokenService;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2RefreshToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;

import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Optional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.Truth8.assertThat;
import static com.google.common.truth.extensions.proto.ProtoTruth.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthorizationCodeRequestHandler}
 */
public class AuthorizationCodeRequestHandlerTest {

    private UserSession userSession;

    private static final String CLIENTID = "client";
    private static final String CLIENTID1 = "client1";
    private static final String SECRET = "secret";
    private static final String REDIRECT_URI = "http://www.google.com";

    private static final String REDIRECT_URI1 = "http://www.facebook.com";

    private static final String LINE = System.lineSeparator();


    private static final ClientDetails CLIENT =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .addRedirectUris(REDIRECT_URI)
                    .addGrantTypes(OAuth2Constants.GrantType.AUTHORIZATION_CODE)
                    .build();

    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String STATE = "state";

    private static final UserDetails USER =
            UserDetails.newBuilder()
                    .setUsername(USERNAME)
                    .setPassword(Hashing.sha256()
                            .hashString(PASSWORD, Charsets.UTF_8).toString())
                    .build();

    AuthorizationCodeRequestHandler authorizationCodeRequestHandler;

    AuthorizationCodeService authorizationCodeService;

    OAuth2TokenService oauth2TokenService;


    OAuth2Request TEST_REQUEST =
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
                                    .setResponseType(OAuth2Constants.ResponseType.CODE)
                                    .setRefreshable(true)
                                    .setGrantType(OAuth2Constants.GrantType.AUTHORIZATION_CODE)
                                    .build())
                    .setAuthorizationResponse(
                            OAuth2Request.AuthorizationResponse.newBuilder()
                                    .setState(STATE)
                                    .setRedirectUri(REDIRECT_URI)
                                    .build())
                    .build();

    OAuth2Request TEST_REQUEST1 =
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
                                    .setResponseType(OAuth2Constants.ResponseType.TOKEN)
                                    .setRefreshable(true)
                                    .setGrantType(OAuth2Constants.GrantType.AUTHORIZATION_CODE)
                                    .build())
                    .setAuthorizationResponse(
                            OAuth2Request.AuthorizationResponse.newBuilder()
                                    .setState(STATE)
                                    .setRedirectUri(REDIRECT_URI)
                                    .build())
                    .build();



    @Before
    public void init() {
        ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.addClient(CLIENT);
        UserDetailsService userDetailsService = new InMemoryUserDetailsService();
        userDetailsService.addUser(USER);
        userSession = new UserSession();
        userSession.setUser(USER);
        authorizationCodeService = new AuthorizationCodeService(new InMemoryCodeStore());
        oauth2TokenService = new InMemoryOAuth2TokenService();
        authorizationCodeRequestHandler = new AuthorizationCodeRequestHandler(
                authorizationCodeService, oauth2TokenService);
    }

    @Test
    public void testHandleCodeRequest_correctRequest_redirect() throws IOException {
        HttpServletResponse response = mock(HttpServletResponse.class);

        assertDoesNotThrow(()-> authorizationCodeRequestHandler.handle(response, TEST_REQUEST));

        verify(response).sendRedirect(
                Matchers.matches(REDIRECT_URI + "\\?code=.{10}&state=" + STATE));
    }

    @Test
    public void testHandleTokenRequest_nonexistentCode_throwInvalidGrantException() {
        HttpServletResponse response = mock(HttpServletResponse.class);

        OAuth2Request.Builder builder = OAuth2Request.newBuilder(TEST_REQUEST1);
        builder.getRequestAuthBuilder().setCode("nonexistence");


        OAuth2Exception e = assertThrows(
                        OAuth2Exception.class,
                        ()-> authorizationCodeRequestHandler.handle(response, builder.build()));

        assertThat(e).isInstanceOf(InvalidGrantException.class);

        assertThat(e.getErrorDescription()).isEqualTo("Non existing code!");
    }

    @Test
    public void testHandleTokenRequest_codeClientIdMismatch_throwInvalidGrantException() {
        HttpServletResponse response = mock(HttpServletResponse.class);

        assertDoesNotThrow(()-> authorizationCodeRequestHandler.handle(response, TEST_REQUEST));

        OAuth2Request.Builder builder = OAuth2Request.newBuilder(TEST_REQUEST1);
        String code = authorizationCodeService.getCodeForRequest(TEST_REQUEST);

        builder.getRequestAuthBuilder().setClientId(CLIENTID1).setCode(code);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> authorizationCodeRequestHandler.handle(response, builder.build()));

        assertThat(e).isInstanceOf(InvalidGrantException.class);

        assertThat(e.getErrorDescription()).isEqualTo("Code client mismatch!");
    }


    @Test
    public void testHandleTokenRequest_codeRedirectUriMismatch_throwInvalidGrantException() {
        HttpServletResponse response = mock(HttpServletResponse.class);

        assertDoesNotThrow(()-> authorizationCodeRequestHandler.handle(response, TEST_REQUEST));

        OAuth2Request.Builder builder = OAuth2Request.newBuilder(TEST_REQUEST1);
        String code = authorizationCodeService.getCodeForRequest(TEST_REQUEST);

        builder.getRequestAuthBuilder().setClientId(CLIENTID).setUsername(USERNAME).setCode(code);
        builder.getAuthorizationResponseBuilder().setRedirectUri(REDIRECT_URI1);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> authorizationCodeRequestHandler.handle(response, builder.build()));

        assertThat(e).isInstanceOf(InvalidGrantException.class);

        assertThat(e.getErrorDescription()).isEqualTo("Redirect uri mismatches the grant!");
    }


    @Test
    public void testHandleTokenRequest_correctRequest_returnToken()
            throws IOException, ParseException {
        HttpServletResponse response = mock(HttpServletResponse.class);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        assertDoesNotThrow(()-> authorizationCodeRequestHandler.handle(response, TEST_REQUEST));

        OAuth2Request.Builder builder = OAuth2Request.newBuilder(TEST_REQUEST1);
        String code = authorizationCodeService.getCodeForRequest(TEST_REQUEST);

        builder.getRequestAuthBuilder().setCode(code);

        assertDoesNotThrow(()-> authorizationCodeRequestHandler.handle(response, builder.build()));

        JSONObject json =
                (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE)
                        .parse(stringWriter.toString());

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
        Optional<OAuth2AccessToken> accessToken =
                oauth2TokenService.readAccessToken(accessTokenString);

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

        assertThat(refreshToken.get())
                .comparingExpectedFieldsOnly().isEqualTo(expectedRefreshToken);
    }


    @Test
    public void testHandleTokenRequest_scopesDoNotMatch_relyOnTheOnRelatedToCode()
            throws IOException, ParseException {
        HttpServletResponse response = mock(HttpServletResponse.class);

        StringWriter stringWriter = new StringWriter();
        PrintWriter writer = new PrintWriter(stringWriter);
        when(response.getWriter()).thenReturn(writer);

        assertDoesNotThrow(()-> authorizationCodeRequestHandler.handle(response, TEST_REQUEST));

        OAuth2Request.Builder builder = OAuth2Request.newBuilder(TEST_REQUEST1);
        String code = authorizationCodeService.getCodeForRequest(TEST_REQUEST);

        builder.getRequestAuthBuilder().setCode(code);
        builder.getRequestBodyBuilder().clearScopes().addScopes("write");

        assertDoesNotThrow(()-> authorizationCodeRequestHandler.handle(response, builder.build()));

        JSONObject json =
                (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE)
                        .parse(stringWriter.toString());

        String accessTokenString = json.getAsString(OAuth2ParameterNames.ACCESS_TOKEN);
        String refreshTokenString = json.getAsString(OAuth2ParameterNames.REFRESH_TOKEN);

        OAuth2AccessToken expectedAccessToken =
                OAuth2AccessToken.newBuilder()
                        .addAllScopes(CLIENT.getScopesList())
                        .build();
        Optional<OAuth2AccessToken> accessToken =
                oauth2TokenService.readAccessToken(accessTokenString);

        assertThat(accessToken).isPresent();

        assertThat(accessToken.get()).comparingExpectedFieldsOnly().isEqualTo(expectedAccessToken);

        OAuth2RefreshToken expectedRefreshToken =
                OAuth2RefreshToken.newBuilder()
                        .addAllScopes(CLIENT.getScopesList())
                        .build();
        Optional<OAuth2RefreshToken> refreshToken =
                oauth2TokenService.readRefreshToken(refreshTokenString);

        assertThat(refreshToken).isPresent();

        assertThat(refreshToken.get())
                .comparingExpectedFieldsOnly().isEqualTo(expectedRefreshToken);
    }

}
