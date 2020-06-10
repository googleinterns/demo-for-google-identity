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

import com.google.common.collect.ImmutableSet;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.security.UserSession;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import org.apache.http.HttpStatus;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Demo AuthorizationEndpoint for OAuth2 Server
 */
@Singleton
public final class AuthorizationEndpoint extends HttpServlet {

    private static final long serialVersionUID = 5L;

    private static final Logger log = Logger.getLogger("AuthorizationCodeEndpoint");

    private final ClientDetailsService clientDetailsService;


    @Inject
    public AuthorizationEndpoint(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }


    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException{

        try {
            String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);

            if (responseType == null) {
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "No Response Type!", null);
            }
            else if (!responseType.equals("token") && !responseType.equals("code")) {
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "Invalid Response Type!", null);
            }

            String clientID = request.getParameter(OAuth2ParameterNames.CLIENT_ID);

            if (clientID == null) {
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "No clientID!", null);
            }

            if(!clientDetailsService.getClientByID(clientID).isPresent()){
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "Invalid clientID!", null);
            }

            ClientDetails client = clientDetailsService.getClientByID(clientID).get();

            String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);

            if (redirectUri == null) {
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "No Redirect URI!", null);
            }

            redirectUri = URLDecoder.decode(redirectUri, "utf-8");

            if (!client.getRedirectUrisList().contains(redirectUri)) {
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "Redirect URI Mismatch!", null);
            }

            Set<String> scope =
                    OAuth2Utils.parseScope(request.getParameter(OAuth2ParameterNames.SCOPE));

            //check if scope is valid
            if (client.getIsScoped()) {
                if (!client.getScopesList().containsAll(scope)) {
                    throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                            "invalid_request", "Scope Not Support!", null);
                }

                if (scope.isEmpty()) {
                    scope = ImmutableSet.copyOf(client.getScopesList());
                }
            }

            String username =
                    ((UserSession) request.getSession().getAttribute("user_session"))
                            .getUser().get().getUsername();

            OAuth2Request.Builder oauth2RequestBuilder =
                    OAuth2Request.newBuilder()
                            .setRequestAuth(
                                    OAuth2Request.RequestAuth.newBuilder()
                                            .setClientId(client.getClientId())
                                            .setUsername(username)
                                            .build())
                            .setRequestBody(
                                    OAuth2Request.RequestBody.newBuilder()
                                            .setIsScoped(!scope.isEmpty())
                                            .addAllScopes(scope)
                                            .setResponseType(responseType)
                                            .setRefreshable(responseType.equals("code"))
                                            .setGrantType(
                                                    responseType.equals("code")
                                                    ? "authorization_code": "implicit")
                                            .build());
            if(request.getParameter(OAuth2ParameterNames.STATE) != null){
                oauth2RequestBuilder.setAuthorizationResponse(
                        OAuth2Request.AuthorizationResponse.newBuilder()
                                .setState(request.getParameter(OAuth2ParameterNames.STATE))
                                .setRedirectUri(redirectUri)
                                .build());
            }
            else{
                oauth2RequestBuilder.setAuthorizationResponse(
                        OAuth2Request.AuthorizationResponse.newBuilder()
                                .setRedirectUri(redirectUri)
                                .build());
            }

            OAuth2Request oauth2Request = oauth2RequestBuilder.build();

            ClientSession clientSession = new ClientSession();
            clientSession.setRequest(oauth2Request);
            request.getSession().setAttribute("client_session", clientSession);

            response.sendRedirect("/oauth2/approval");
        }
        catch(OAuth2Exception exception){
            log.info(exception.getErrorInfo().orElse(""));
            OAuth2Utils.returnHttpError(response, exception);
        }
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException, UnsupportedOperationException{
        if(request.getParameter("user_approval") == null
                && request.getParameter("user_deny") == null){
            doGet(request, response);
            return;
        }
        try{
            String userApproval = request.getParameter("user_approval");

            String userDeny = request.getParameter("user_deny");

            if(Objects.equals(userDeny, "true")){
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "User Deny!", null);
            }
            if(!Objects.equals(userApproval, "true")){
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "No Approval!", null);
            }
            Optional<OAuth2Request> oauth2Request =
                    ((ClientSession) request.getSession().getAttribute("client_session"))
                            .getRequest();
            if(!oauth2Request.isPresent()){
                throw new OAuth2Exception(HttpStatus.SC_BAD_REQUEST,
                        "invalid_request", "No OAuth2Request!", null);
            }
            //do token processing, add later
        }
        catch(OAuth2Exception exception){
            log.info(exception.getErrorInfo().orElse(""));
            OAuth2Utils.returnHttpError(response, exception);
        }

    }

}

