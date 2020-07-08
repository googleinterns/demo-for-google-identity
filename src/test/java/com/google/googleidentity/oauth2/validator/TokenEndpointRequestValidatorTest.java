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

package com.google.googleidentity.oauth2.validator;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.exception.*;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.testtools.FakeHttpSession;
import com.google.googleidentity.user.UserDetails;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TokenEndpointRequestValidatorTest {
    private ClientSession clientSession;

    private ClientDetailsService clientDetailsService;


    private static final String CLIENTID = "google";
    private static final String SECRET = "secret";
    private static final String REDIRECT_URI_REGEX= "http://www.google.com/";
    private static final String REDIRECT_URI= "http://www.google.com/123";

    private static final ImmutableList<GrantType> TESTGRANTTYPES = ImmutableList.of(
            GrantType.AUTHORIZATION_CODE,
            GrantType.IMPLICIT,
            GrantType.REFRESH_TOKEN,
            GrantType.JWT_ASSERTION);

    private static final ClientDetails CLIENT =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .addRedirectUris(REDIRECT_URI_REGEX)
                    .addAllGrantTypes(TESTGRANTTYPES)
                    .build();

    private static final ClientDetails CLIENT1 =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .addRedirectUris(REDIRECT_URI_REGEX)
                    .addGrantTypes(GrantType.IMPLICIT)
                    .build();

    private static final String USERNAME = "111";
    private static final String PASSWORD = "111";

    private static final UserDetails USER =
            UserDetails.newBuilder()
                    .setUsername(USERNAME)
                    .setPassword(Hashing.sha256()
                            .hashString(PASSWORD, Charsets.UTF_8).toString())
                    .build();

    @Before
    public void init(){
        clientDetailsService = new InMemoryClientDetailsService();
        clientDetailsService.addClient(CLIENT);
        UserSession userSession = new UserSession();
        userSession.setUser(USER);
        clientSession = new ClientSession();
        clientSession.setClient(CLIENT);
    }

    @Test
    public void test_validatePost_unsupportedGrantTypes_throwUnsupportedGrantTypeException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)).thenReturn("not_support");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.CODE)).thenReturn("auth_code");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(UnsupportedGrantTypeException.class);

    }


    @Test
    public void test_validatePost_ImplicitGrantType_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.IMPLICIT);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.CODE)).thenReturn("auth_code");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);

        assertThat(e.getErrorDescription()).isEqualTo(
                "Implicit flow is not supported at token endpoint!");

    }


    @Test
    public void test_validatePost_userCannotUserTheGrantType_throwUnauthorizedClientException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        ClientSession clientSession1 = new ClientSession();

        clientSession1.setClient(CLIENT1);

        httpSession.setAttribute("client_session", clientSession1);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.AUTHORIZATION_CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.CODE)).thenReturn("auth_code");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(UnauthorizedClientException.class);
    }

    @Test
    public void test_validateAuthCodeRequest_noRedirectUri_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.AUTHORIZATION_CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.CODE)).thenReturn("auth_code");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);

        assertThat(e.getErrorDescription()).isEqualTo("No Redirect Uri!");

    }


    @Test
    public void test_validateAuthCodeRequest_noCode_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.AUTHORIZATION_CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.CODE)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);

        assertThat(e.getErrorDescription()).isEqualTo("No authorization code!");

    }

    @Test
    public void test_validateAuthCodeRequest_Correct_doNotThrowException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.AUTHORIZATION_CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.CODE)).thenReturn("auth_code");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        assertDoesNotThrow(()-> TokenEndpointRequestValidator.validatePost(request));

    }

    @Test
    public void test_validateRefreshTokenRequest_noRefreshToken_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.REFRESH_TOKEN);
        when(request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);

        assertThat(e.getErrorDescription()).isEqualTo("No refresh_token!");

    }

    @Test
    public void test_validateRefreshTokenRequest_Correct_doNotThrowException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.REFRESH_TOKEN);
        when(request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN)).thenReturn("refresh_token");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        assertDoesNotThrow(()-> TokenEndpointRequestValidator.validatePost(request));

    }


    @Test
    public void test_validateJwtAssertion_noIntent_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.JWT_ASSERTION);
        when(request.getParameter(OAuth2ParameterNames.INTENT)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.ASSERTION)).thenReturn("assertion");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);

        assertThat(e.getErrorDescription()).isEqualTo("No Intent!");

    }

    @Test
    public void test_validateJwtAssertion_unsupportedIntent_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.JWT_ASSERTION);
        when(request.getParameter(OAuth2ParameterNames.INTENT)).thenReturn("unsupported");
        when(request.getParameter(OAuth2ParameterNames.ASSERTION)).thenReturn("assertion");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);

        assertThat(e.getErrorDescription()).isEqualTo("Unsupported intent!");

    }


    @Test
    public void test_validateJwtAssertion_noAssertion_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.JWT_ASSERTION);
        when(request.getParameter(OAuth2ParameterNames.INTENT))
                .thenReturn(OAuth2Constants.JwtAssertionIntents.CREATE);
        when(request.getParameter(OAuth2ParameterNames.ASSERTION)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> TokenEndpointRequestValidator
                        .validatePost(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);

        assertThat(e.getErrorDescription()).isEqualTo("No assertion!");

    }

    @Test
    public void test_validateJwtAssertion_Correct_doNotThrowException() {

        HttpServletRequest request = mock(HttpServletRequest.class);
        FakeHttpSession httpSession = new FakeHttpSession();

        httpSession.setAttribute("client_session", clientSession);

        when(request.getParameter(OAuth2ParameterNames.GRANT_TYPE))
                .thenReturn(OAuth2Constants.GrantType.JWT_ASSERTION);
        when(request.getParameter(OAuth2ParameterNames.INTENT))
                .thenReturn(OAuth2Constants.JwtAssertionIntents.CREATE);
        when(request.getParameter(OAuth2ParameterNames.ASSERTION)).thenReturn("assertion");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getSession()).thenReturn(httpSession);

        assertDoesNotThrow(()-> TokenEndpointRequestValidator.validatePost(request));

    }

}
