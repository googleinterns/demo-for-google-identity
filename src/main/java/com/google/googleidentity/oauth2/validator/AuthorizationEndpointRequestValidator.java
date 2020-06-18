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

import com.google.common.collect.ImmutableSet;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.*;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static com.google.googleidentity.oauth2.exception.OAuth2Exception.ErrorCode;

public class AuthorizationEndpointRequestValidator {

    private static final Logger log = Logger.getLogger("AuthorizationEndpointParameterValidator");

    public static void validateGET(
            HttpServletRequest request,
            ClientDetailsService clientDetailsService) throws OAuth2Exception {

        String clientID = request.getParameter(OAuth2ParameterNames.CLIENT_ID);

        if (clientID == null) {
            throw new InvalidRequestException(ErrorCode.NO_CLIENT_ID);
        }

        if(!clientDetailsService.getClientByID(clientID).isPresent()){
            throw new InvalidRequestException(ErrorCode.NONEXISTENT_CLIENT_ID);
        }

        ClientDetails client = clientDetailsService.getClientByID(clientID).get();

        String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);

        if(redirectUri == null){
            throw new InvalidRequestException(ErrorCode.NO_REDIRECT_URI);
        }

        try {
            redirectUri = URLDecoder.decode(redirectUri, "utf-8");
        } catch (UnsupportedEncodingException e) {
            log.log(Level.INFO, "Uri decode failed", e);
        }

        if (!client.getRedirectUrisList().contains(redirectUri)) {
            throw new InvalidRequestException(ErrorCode.REDIRECT_URI_MISMATCH);
        }

        String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);

        if(request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) == null){
            throw new InvalidRequestException(ErrorCode.NO_RESPONSE_TYPE);
        }
        else if (!responseType.equals("token") && !responseType.equals("code")) {
            throw new UnsupportedResponseTypeException();
        }

        String grantType = responseType.equals("token") ? "implicit" : "authorization_code";

        if(!client.getGrantTypesList().contains(grantType)){
            throw new UnauthorizedClientException();
        }

        if (request.getParameter(OAuth2ParameterNames.SCOPE) != null && client.getIsScoped()) {
            Set<String> scope =
                    OAuth2Utils.parseScope(request.getParameter(OAuth2ParameterNames.SCOPE));
            if (!client.getScopesList().containsAll(scope)) {
                throw new InvalidScopeException();
            }
        }
    }

    public static void validatePOST(HttpServletRequest request) throws OAuth2Exception {
        String userConsent = request.getParameter("user_approve");
        String userDeny = request.getParameter("user_deny");

        if(!OAuth2Utils.getClientSession(request).getRequest().isPresent()){
            throw new InvalidRequestException(ErrorCode.NO_AUTHORIZATION_REQUEST);
        }
        if(Objects.equals(userDeny, "true")){
            throw new AccessDeniedException();
        }

        if(!Objects.equals(userConsent, "true")){
            throw new InvalidRequestException(ErrorCode.NO_USER_CONSENT);
        }
    }


}
