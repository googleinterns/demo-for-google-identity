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

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.exception.InvalidGrantException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.UnauthorizedClientException;
import com.google.googleidentity.oauth2.exception.UnsupportedGrantTypeException;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;

import javax.servlet.http.HttpServletRequest;
import java.util.Set;

public class TokenEndpointRequestValidator {

    private static final Set<String> supportedGrantTypes =
            ImmutableSet.of(
                    "authorization_code",
                    "implicit",
                    "refresh_token",
                    "urn:ietf:params:oauth:grant-type:jwt-bearer");

    private static final Set<String> supportedIntents =
            ImmutableSet.of("check", "get", "create");

    public static void validatePost(HttpServletRequest request) throws OAuth2Exception {

        // Should be there since it has passed ClientAuthentication Filter
        ClientDetails client = OAuth2Utils.getClientSession(request).getClient().get();

        // Not null since it has been checked in ClientAuthentication Filter
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (!supportedGrantTypes.contains(grantType)) {
            throw new UnsupportedGrantTypeException();
        }

        if (grantType.equals("implicit")) {
            throw new InvalidGrantException(
                    InvalidGrantException.ErrorCode.IMPLICIT_GRANT_IN_TOKEN_ENDPOINT);
        }

        if (!client.getGrantTypesList().contains(grantType)) {
            throw new UnauthorizedClientException();
        }

        if (grantType.equals("authorization_code")) {
            validateAuthCodeRequest(request);
        }

        if (grantType.equals("refresh_token")) {
            validateRefreshTokenRequest(request);
        }

        if (grantType.equals("urn:ietf:params:oauth:grant-type:jwt-bearer")) {
            validateJwtAssertion(request);
        }
    }

    private static void validateAuthCodeRequest(HttpServletRequest request) throws OAuth2Exception {
        if (Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.REDIRECT_URI))) {
            throw new InvalidGrantException(InvalidGrantException.ErrorCode.NO_REDIRECT_URI);
        }
        if (Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.CODE))) {
            throw new InvalidGrantException(InvalidGrantException.ErrorCode.NO_AUTHORIZATION_CODE);
        }
    }

    private static void validateRefreshTokenRequest(HttpServletRequest request)
            throws OAuth2Exception {
        if (Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.REFRESH_TOKEN))) {
            throw new InvalidGrantException(InvalidGrantException.ErrorCode.NO_REFRESH_TOKEN);
        }
    }

    private static void validateJwtAssertion(HttpServletRequest request) throws OAuth2Exception {
        String intent = request.getParameter(OAuth2ParameterNames.INTENT);
        if (Strings.isNullOrEmpty(intent)) {
            throw new InvalidGrantException(InvalidGrantException.ErrorCode.NO_INTENT);
        }

        if (!supportedIntents.contains(intent)) {
            throw new InvalidGrantException(InvalidGrantException.ErrorCode.UNSUPPORTED_INTENT);
        }
        if (Strings.isNullOrEmpty(request.getParameter(OAuth2ParameterNames.ASSERTION))) {
            throw new InvalidGrantException(InvalidGrantException.ErrorCode.NO_ASSERTION);
        }
    }
}
