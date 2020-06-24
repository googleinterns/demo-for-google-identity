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

package com.google.googleidentity.oauth2.endpoint;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.oauth2.validator.AuthorizationEndpointRequestValidator;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Demo AuthorizationEndpoint for OAuth2 Server
 */
@Singleton
public final class AuthorizationEndpoint extends HttpServlet {

    private static final long serialVersionUID = 5L;

    private static final Logger log = Logger.getLogger("AuthorizationEndpoint");

    private final ClientDetailsService clientDetailsService;


    @Inject
    public AuthorizationEndpoint(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }


    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException {
        try {
            AuthorizationEndpointRequestValidator.validateClientAndRedirectUri(
                    request, clientDetailsService);
        } catch (InvalidRequestException exception) {
            log.info(
                    "Failed in validating client and redirect URI in Authorization Endpoint." +
                    "Error Type: " + exception.getErrorType() +
                    "Description: " + exception.getErrorDescription());
            response.setStatus(exception.getHttpCode());
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().println(
                    OAuth2ExceptionHandler.getResponseBody(exception).toJSONString());
            response.getWriter().flush();
            return;
        }

        try {
            AuthorizationEndpointRequestValidator.validateGET(request, clientDetailsService);
        } catch (OAuth2Exception exception) {
            log.info(
                    "Failed in validating Get request in Authorization Endpoint." +
                            "Error Type: " + exception.getErrorType() +
                            "Description: " + exception.getErrorDescription());
            response.sendRedirect(
                    OAuth2ExceptionHandler.getFullRedirectUrl(
                            exception,
                            request.getParameter(OAuth2ParameterNames.REDIRECT_URI),
                            request.getParameter(OAuth2ParameterNames.STATE)));
            return;
        }

        ClientSession clientSession = new ClientSession();
        clientSession.setRequest(parseOAuth2RequestFromHttpRequest(request));
        OAuth2Utils.setClientSession(request, clientSession);

        response.sendRedirect("/oauth2/consent");
    }

    /**
     * when user approve or deny the consent, the request will sent here
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException {
        try {
            AuthorizationEndpointRequestValidator.validatePOST(request);
        } catch (OAuth2Exception exception) {
            log.info(exception.getErrorType() + exception.getErrorDescription());
            if (OAuth2Utils.getClientSession(request).getRequest().isPresent()) {
                response.sendRedirect(
                        OAuth2ExceptionHandler.getFullRedirectUrl(
                                exception,
                                OAuth2Utils.getClientSession(request).getRequest().get()
                                        .getAuthorizationResponse().getRedirectUri(),
                                OAuth2Utils.getClientSession(request).getRequest().get()
                                        .getAuthorizationResponse().getState()));
            } else {
                log.info(
                        "Failed in validating Post request in Authorization Endpoint." +
                                "Error Type: " + exception.getErrorType() +
                                "Description: " + exception.getErrorDescription());
                response.setStatus(exception.getHttpCode());
                response.setContentType("application/json;charset=UTF-8");
                response.getWriter().println(
                        OAuth2ExceptionHandler.getResponseBody(exception).toJSONString());
                response.getWriter().flush();
            }
            return;
        }
    }

    /**
     * Should be call after all validation in doGet function
     */
    private OAuth2Request parseOAuth2RequestFromHttpRequest(HttpServletRequest request) {
        String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);

        String clientID = request.getParameter(OAuth2ParameterNames.CLIENT_ID);

        ClientDetails client = clientDetailsService.getClientByID(clientID).get();

        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);

        try {
            redirectUri = URLDecoder.decode(redirectUri, "utf-8");
        } catch (UnsupportedEncodingException e) {
            // This should never happen.
            throw new IllegalStateException(
                    "URL should have been decoded during request validation", e);
        }

        Set<String> scope = OAuth2Utils.parseScope(
                request.getParameter(OAuth2ParameterNames.SCOPE));

        // Set default scopes
        if (client.getIsScoped() && scope.isEmpty()) {
            scope = ImmutableSet.copyOf(client.getScopesList());
        }

        OAuth2Request.Builder oauth2RequestBuilder =
                OAuth2Request.newBuilder()
                        .setRequestAuth(
                                OAuth2Request.RequestAuth.newBuilder()
                                        .setClientId(client.getClientId())
                                        .setUsername(
                                                OAuth2Utils.getUserSession(request).getUser().get()
                                                        .getUsername())
                                        .build())
                        .setRequestBody(
                                OAuth2Request.RequestBody.newBuilder()
                                        .setIsScoped(!scope.isEmpty())
                                        .addAllScopes(scope)
                                        .setResponseType(responseType)
                                        .setRefreshable(responseType.equals("code"))
                                        .setGrantType(
                                                OAuth2Utils.getGrantTypeFromResponseType(
                                                        responseType))
                                        .build());

        oauth2RequestBuilder.getAuthorizationResponseBuilder()
                .setRedirectUri(redirectUri);

        if (!Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.STATE))) {
            oauth2RequestBuilder.getAuthorizationResponseBuilder()
                    .setState(request.getParameter(OAuth2ParameterNames.STATE));
        }

        return oauth2RequestBuilder.build();
    }

}

