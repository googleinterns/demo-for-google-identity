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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.oauth2.validator.TokenEndpointRequestValidator;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.logging.Logger;

/**
 * Token exchange endpoint in OAuth2 Server
 */
@Singleton
public class TokenEndpoint extends HttpServlet {

    private static final long serialVersionUID = 5L;

    private static final Logger log = Logger.getLogger("TokenEndpoint");

    private final ClientDetailsService clientDetailsService;


    @Inject
    public TokenEndpoint(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException {

        OAuth2Exception exception =
                new InvalidRequestException(
                        InvalidRequestException.ErrorCode.UNSUPPORTED_REQUEST_METHOD);
        log.info("Token endpoint does not support GET request." );
        OAuth2ExceptionHandler.handle(exception, response);
        return;
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException {
        try {
            TokenEndpointRequestValidator.validatePost(request);
        } catch(OAuth2Exception exception) {
            log.info(
                    "Failed in validating Post request in Token Endpoint." +
                            "Error Type: " + exception.getErrorType() +
                            "Description: " + exception.getErrorDescription());
            OAuth2ExceptionHandler.handle(exception, response);
            return;
        }

        OAuth2Request oauth2Request = parseOAuth2RequestFromHttpRequest(request);
    }

    /**
     * Should be called after all validation in doPost function.
     */
    public OAuth2Request parseOAuth2RequestFromHttpRequest(HttpServletRequest request) {

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        Preconditions.checkArgument(
                OAuth2Utils.getClientSession(request).getClient().isPresent(),
                "Client should have been set in client filter!");

        OAuth2Request.Builder oauth2RequestBuilder = OAuth2Request.newBuilder();
        oauth2RequestBuilder.getRequestAuthBuilder()
                .setClientId(
                            OAuth2Utils.getClientSession(request).getClient().get().getClientId());

        oauth2RequestBuilder.getRequestBodyBuilder()
                .setGrantType(grantType).setResponseType(OAuth2Constants.ResponseType.TOKEN);

        if (grantType.equals(OAuth2Constants.GrantType.AUTHORIZATION_CODE)) {
            oauth2RequestBuilder.getRequestAuthBuilder().setCode(
                    request.getParameter(OAuth2ParameterNames.CODE));
            try {
                oauth2RequestBuilder.getAuthorizationResponseBuilder().setRedirectUri(
                        URLDecoder.decode(
                                request.getParameter(OAuth2ParameterNames.REDIRECT_URI),
                                "utf-8"));
            } catch (UnsupportedEncodingException e) {
                // This should never happen, since we have validated it before
                throw new IllegalStateException(
                        "URL should be valid", e);
            }

        } else if (grantType.equals(OAuth2Constants.GrantType.REFRESH_TOKEN)) {
            oauth2RequestBuilder.getRequestBodyBuilder().setRefreshToken(
                    request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN));
        } else if (grantType.equals(OAuth2Constants.GrantType.JWT_ASSERTION)) {
            oauth2RequestBuilder.getRequestBodyBuilder()
                    .setIntent(request.getParameter(OAuth2ParameterNames.INTENT))
                    .setAssertion(request.getParameter(OAuth2ParameterNames.ASSERTION));
            if (!Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.SCOPE))) {
                oauth2RequestBuilder.getRequestBodyBuilder()
                        .setIsScoped(true).addAllScopes(
                                OAuth2Utils.parseScope(
                                        request.getParameter(OAuth2ParameterNames.SCOPE)));
            }
            // Just used for test, will be removed later
            log.info("Assertion: " + request.getParameter(OAuth2ParameterNames.ASSERTION));
        }
        return oauth2RequestBuilder.build();
    }
}
