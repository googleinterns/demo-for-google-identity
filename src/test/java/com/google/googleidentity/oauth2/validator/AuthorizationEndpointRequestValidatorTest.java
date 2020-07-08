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
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.InvalidScopeException;
import com.google.googleidentity.oauth2.exception.AccessDeniedException;

import com.google.googleidentity.oauth2.exception.UnauthorizedClientException;
import com.google.googleidentity.oauth2.exception.UnsupportedResponseTypeException;
import com.google.googleidentity.oauth2.request.OAuth2Request;
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


public class AuthorizationEndpointRequestValidatorTest {

    private ClientSession clientSession;

    private ClientDetailsService clientDetailsService;


    private static final String CLIENTID = "client";
    private static final String SECRET = "secret";
    private static final String REDIRECT_URI_REGEX= "http://www.google.com/";
    private static final String REDIRECT_URI= "http://www.google.com/123";

    private static final ClientDetails CLIENT =
            ClientDetails.newBuilder()
                    .setClientId(CLIENTID)
                    .setSecret(Hashing.sha256()
                            .hashString(SECRET, Charsets.UTF_8).toString())
                    .addScopes("read")
                    .setIsScoped(true)
                    .addRedirectUris(REDIRECT_URI_REGEX)
                    .addGrantTypes(GrantType.AUTHORIZATION_CODE)
                    .build();

    private static final String USERNAME = "usernames";
    private static final String PASSWORD = "password";

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
    }

    @Test
    public void test_validateClientAndRedirectUri_NoClientID_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
                .thenReturn(OAuth2Constants.ResponseType.CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validateClientAndRedirectUri(request, clientDetailsService));

        assertThat(e).isInstanceOf(InvalidRequestException.class);
        assertThat(e.getErrorDescription()).isEqualTo("No Client ID!");

    }

    @Test
    public void test_validateClientAndRedirectUri_NonExistedClientID_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
                .thenReturn(OAuth2Constants.ResponseType.CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn("non_existed");
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validateClientAndRedirectUri(request, clientDetailsService));

        assertThat(e).isInstanceOf(InvalidRequestException.class);
        assertThat(e.getErrorDescription()).isEqualTo("Client ID does not exist!");

    }

    @Test
    public void test_validateClientAndRedirectUri_NoRedirectUri_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
                .thenReturn(OAuth2Constants.ResponseType.CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validateClientAndRedirectUri(request, clientDetailsService));

        assertThat(e).isInstanceOf(InvalidRequestException.class);
        assertThat(e.getErrorDescription()).isEqualTo("No Redirect Uri!");

    }


    @Test
    public void test_validateClientAndRedirectUri_WrongRedirectUri_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
                .thenReturn(OAuth2Constants.ResponseType.CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn("wrong_uri");
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validateClientAndRedirectUri(request, clientDetailsService));

        assertThat(e).isInstanceOf(InvalidRequestException.class);
        assertThat(e.getErrorDescription()).isEqualTo("Redirect Uri Mismatch!");

    }

    @Test
    public void test_validateGet_NoResponseType_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn(null);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validateGET(request, clientDetailsService));

        assertThat(e).isInstanceOf(InvalidRequestException.class);
        assertThat(e.getErrorDescription()).isEqualTo("No Response Type!");
    }

    @Test
    public void test_validateGet_UnsupportedResponseType_throwUnsupportedResponseTypeException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE)).thenReturn("unsupported");
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validateGET(request, clientDetailsService));

        assertThat(e).isInstanceOf(UnsupportedResponseTypeException.class);
    }

    @Test
    public void test_validateGet_UnauthorizedGrantType_throwUnauthorizedClientException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
                .thenReturn(OAuth2Constants.ResponseType.TOKEN);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("invalid");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validateGET(request, clientDetailsService));

        assertThat(e).isInstanceOf(UnauthorizedClientException.class);
    }

    @Test
    public void test_validateGet_InvalidScope_throwInvalidScopeException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
                .thenReturn(OAuth2Constants.ResponseType.CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("invalid");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validateGET(request, clientDetailsService));

        assertThat(e).isInstanceOf(InvalidScopeException.class);
    }

    @Test
    public void test_validateGet_allRight_noException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE))
                .thenReturn(OAuth2Constants.ResponseType.CODE);
        when(request.getParameter(OAuth2ParameterNames.CLIENT_ID)).thenReturn(CLIENTID);
        when(request.getParameter(OAuth2ParameterNames.REDIRECT_URI)).thenReturn(REDIRECT_URI);
        when(request.getParameter(OAuth2ParameterNames.SCOPE)).thenReturn("read");
        when(request.getParameter(OAuth2ParameterNames.STATE)).thenReturn("111");

        assertDoesNotThrow(
                ()-> AuthorizationEndpointRequestValidator
                        .validateGET(request, clientDetailsService));

    }

    @Test
    public void test_validatePost_NoRequestInSession_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("user_approve")).thenReturn("true");
        FakeHttpSession httpSession = new FakeHttpSession();
        when(request.getSession()).thenReturn(httpSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validatePOST(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);
        assertThat(e.getErrorDescription()).isEqualTo("No request need to approve!");
    }


    @Test
    public void test_validatePost_userDeny_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("user_approve")).thenReturn("false");
        FakeHttpSession httpSession = new FakeHttpSession();
        when(request.getSession()).thenReturn(httpSession);

        clientSession.setRequest(OAuth2Request.newBuilder().build());
        httpSession.setAttribute("client_session", clientSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validatePOST(request));

        assertThat(e).isInstanceOf(AccessDeniedException.class);
    }


    @Test
    public void test_validatePost_userConsentMissing_throwInvalidRequestException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("user_approve")).thenReturn(null);
        FakeHttpSession httpSession = new FakeHttpSession();
        when(request.getSession()).thenReturn(httpSession);

        clientSession.setRequest(OAuth2Request.newBuilder().build());
        httpSession.setAttribute("client_session", clientSession);

        OAuth2Exception e = assertThrows(
                OAuth2Exception.class,
                ()-> AuthorizationEndpointRequestValidator
                        .validatePOST(request));

        assertThat(e).isInstanceOf(InvalidRequestException.class);
        assertThat(e.getErrorDescription()).isEqualTo("No User consent information!");
    }


    @Test
    public void test_validatePost_allRight_noException() {

        HttpServletRequest request = mock(HttpServletRequest.class);

        when(request.getParameter("user_approve")).thenReturn("true");
        when(request.getParameter("user_deny")).thenReturn(null);
        FakeHttpSession httpSession = new FakeHttpSession();
        when(request.getSession()).thenReturn(httpSession);

        clientSession.setRequest(OAuth2Request.newBuilder().build());
        httpSession.setAttribute("client_session", clientSession);

        assertDoesNotThrow(
                ()-> AuthorizationEndpointRequestValidator
                        .validatePOST(request));
    }


}
