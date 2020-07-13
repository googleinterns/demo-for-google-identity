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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.InvalidScopeException;
import com.google.googleidentity.oauth2.exception.AccessDeniedException;
import com.google.googleidentity.oauth2.exception.UnauthorizedClientException;
import com.google.googleidentity.oauth2.exception.UnsupportedResponseTypeException;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2EnumMap;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;

import javax.servlet.http.HttpServletRequest;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Optional;
import java.util.Set;

public class AuthorizationEndpointRequestValidator {

  /**
   * Check whether the client and redirect uri is valid in a Get request to authorization endpoint
   */
  public static void validateClientAndRedirectUri(
      HttpServletRequest request, ClientDetailsService clientDetailsService)
      throws InvalidRequestException {
    String clientID = request.getParameter(OAuth2ParameterNames.CLIENT_ID);

    if (Strings.isNullOrEmpty(clientID)) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_CLIENT_ID);
    }

    Optional<ClientDetails> client = clientDetailsService.getClientByID(clientID);

    if (!client.isPresent()) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NONEXISTENT_CLIENT_ID);
    }

    String redirectUri = request.getParameter(OAuth2ParameterNames.REDIRECT_URI);

    if (Strings.isNullOrEmpty(redirectUri)) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_REDIRECT_URI);
    }

    try {
      redirectUri = URLDecoder.decode(redirectUri, "utf-8");
    } catch (UnsupportedEncodingException e) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NON_URL_ENCODED_URI);
    }

    if (!OAuth2Utils.matchUri(client.get().getRedirectUrisList(), redirectUri)) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.REDIRECT_URI_MISMATCH);
    }
  }

  /**
   * Check whether the Get request is valid in authorization endpoint, Must be call after
   * validateRedirectUri function
   */
  public static void validateGET(
      HttpServletRequest request, ClientDetailsService clientDetailsService)
      throws OAuth2Exception {

    // here the clientID has been checked in validateRedirectUri function
    String clientID = request.getParameter(OAuth2ParameterNames.CLIENT_ID);

    Preconditions.checkArgument(
        clientDetailsService.getClientByID(clientID).isPresent(),
        "Client should have been checked in previous validation");

    ClientDetails client = clientDetailsService.getClientByID(clientID).get();

    String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);

    if (Strings.isNullOrEmpty(responseType)) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_RESPONSE_TYPE);
    } else if (!responseType.equals(OAuth2Constants.ResponseType.CODE)
        && !responseType.equals(OAuth2Constants.ResponseType.TOKEN)) {
      throw new UnsupportedResponseTypeException();
    }

    GrantType grantType =
        OAuth2EnumMap.GRANT_TYPE_MAP.get(OAuth2Utils.getGrantTypeFromResponseType(responseType));

    if (!client.getGrantTypesList().contains(grantType)) {
      throw new UnauthorizedClientException();
    }

    if (!Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.SCOPE))
        && client.getIsScoped()) {
      Set<String> scope = OAuth2Utils.parseScope(request.getParameter(OAuth2ParameterNames.SCOPE));
      if (!client.getScopesList().containsAll(scope)) {
        throw new InvalidScopeException();
      }
    }
  }

  /**
   * Check whether the Post request is valid in authorization endpoint. It is not defined in OAuth
   * 2.0 spec RFC6749. It is used to handle user consent
   */
  public static void validatePOST(HttpServletRequest request) throws OAuth2Exception {
    String userConsent = request.getParameter("user_approve");

    if (!OAuth2Utils.getClientSession(request).getRequest().isPresent()) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_AUTHORIZATION_REQUEST);
    }

    if (Strings.isNullOrEmpty(userConsent)) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_USER_CONSENT);
    }

    if (userConsent.equals("false")) {
      throw new AccessDeniedException();
    } else if (!userConsent.equals("true")) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.INVALID_USER_CONSENT);
    }
  }
}
