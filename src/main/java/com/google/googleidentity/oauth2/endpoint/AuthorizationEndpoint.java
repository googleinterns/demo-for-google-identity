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

import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.validator.AuthorizationEndpointRequestValidator;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
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
        try{
            AuthorizationEndpointRequestValidator.validateRedirectUri(
                    request, clientDetailsService);
        } catch (OAuth2Exception exception) {
            log.info(exception.getErrorType() + exception.getErrorDescription());
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
            log.info(exception.getErrorType() + exception.getErrorDescription());
            response.sendRedirect(
                    OAuth2ExceptionHandler.getFullRedirectUrl(
                            exception,
                            request.getParameter(OAuth2ParameterNames.REDIRECT_URI),
                            request.getParameter(OAuth2ParameterNames.STATE)));
            return;
        }
    }

    /**
     * when user approve or deny the consent, the request will sent here
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException {
        try{
            AuthorizationEndpointRequestValidator.validatePOST(request);
        } catch (OAuth2Exception exception) {
            log.info(exception.getErrorType() + exception.getErrorDescription());
            response.sendRedirect(
                    OAuth2ExceptionHandler.getFullRedirectUrl(
                            exception,
                            request.getParameter(OAuth2ParameterNames.REDIRECT_URI),
                            request.getParameter(OAuth2ParameterNames.STATE)));
            return;
        }
    }

}

