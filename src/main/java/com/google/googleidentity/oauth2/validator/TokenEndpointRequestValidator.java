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
import com.google.common.collect.ImmutableSet;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.UnauthorizedClientException;
import com.google.googleidentity.oauth2.exception.UnsupportedGrantTypeException;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Set;

public final class TokenEndpointRequestValidator {

  private static final Set<String> supportedGrantTypes =
      ImmutableSet.of(
          OAuth2Constants.GrantType.AUTHORIZATION_CODE,
          OAuth2Constants.GrantType.IMPLICIT,
          OAuth2Constants.GrantType.JWT_ASSERTION,
          OAuth2Constants.GrantType.REFRESH_TOKEN);

  private static final Set<String> supportedIntents =
      ImmutableSet.of(
          OAuth2Constants.JwtAssertionIntents.CREATE,
          OAuth2Constants.JwtAssertionIntents.CHECK,
          OAuth2Constants.JwtAssertionIntents.GET);

  public static void validatePost(HttpServletRequest request) throws OAuth2Exception {

    Preconditions.checkArgument(
        OAuth2Utils.getClientSession(request).getClient().isPresent(),
        "Client Should be there since it has passed ClientAuthentication Filter!");

    ClientDetails client = OAuth2Utils.getClientSession(request).getClient().get();

    Preconditions.checkArgument(
        !Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)),
        "Grant type is not null since it has been checked in ClientAuthentication Filter");

    String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

    switch (grantType) {
      case OAuth2Constants.GrantType.IMPLICIT:
        if (!client.getGrantTypesList().contains(GrantType.IMPLICIT)) {
          throw new UnauthorizedClientException();
        }
        throw new InvalidRequestException(
            InvalidRequestException.ErrorCode.IMPLICIT_GRANT_IN_TOKEN_ENDPOINT);
      case OAuth2Constants.GrantType.AUTHORIZATION_CODE:
        if (!client.getGrantTypesList().contains(GrantType.AUTHORIZATION_CODE)) {
          throw new UnauthorizedClientException();
        }
        validateAuthCodeRequest(request);
        break;
      case OAuth2Constants.GrantType.REFRESH_TOKEN:
        if (!client.getGrantTypesList().contains(GrantType.REFRESH_TOKEN)) {
          throw new UnauthorizedClientException();
        }
        validateRefreshTokenRequest(request);
        break;
      case OAuth2Constants.GrantType.JWT_ASSERTION:
        if (!client.getGrantTypesList().contains(GrantType.JWT_ASSERTION)) {
          throw new UnauthorizedClientException();
        }
        validateJwtAssertion(request);
        break;
      default:
        throw new UnsupportedGrantTypeException();
    }
  }

  private static void validateAuthCodeRequest(HttpServletRequest request) throws OAuth2Exception {
    if (Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.REDIRECT_URI))) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_REDIRECT_URI);
    }
    try {
      URLDecoder.decode(request.getParameter(OAuth2ParameterNames.REDIRECT_URI), "utf-8");
    } catch (UnsupportedEncodingException e) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NON_URL_ENCODED_URI);
    }
    if (Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.CODE))) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_AUTHORIZATION_CODE);
    }
  }

  private static void validateRefreshTokenRequest(HttpServletRequest request)
      throws OAuth2Exception {
    if (Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN))) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_REFRESH_TOKEN);
    }
  }

  private static void validateJwtAssertion(HttpServletRequest request) throws OAuth2Exception {
    String intent = request.getParameter(OAuth2ParameterNames.INTENT);
    if (Strings.isNullOrEmpty(intent)) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_INTENT);
    }

    if (!supportedIntents.contains(intent)) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.UNSUPPORTED_INTENT);
    }
    if (Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.ASSERTION))) {
      throw new InvalidRequestException(InvalidRequestException.ErrorCode.NO_ASSERTION);
    }
  }
}
