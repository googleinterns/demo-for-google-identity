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
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.InvalidRequestException.ErrorCode;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.util.OAuth2Constants.TokenTypes;
import com.google.googleidentity.oauth2.util.OAuth2EnumMap;
import javax.servlet.http.HttpServletRequest;

public final class TokenRevokeEndpointRequestValidator {
  /**
   * Check whether the Post request is valid in token revoke endpoint.
   */
  private static final ImmutableSet<String> SUPPORT_TOKEN_TYPES =
      ImmutableSet.of(TokenTypes.ACCESS_TOKEN,TokenTypes.REFRESH_TOKEN);
  public static void validatePOST(HttpServletRequest request) throws OAuth2Exception {
    if (Strings.isNullOrEmpty(request.getParameter("token"))) {
      throw new InvalidRequestException(ErrorCode.NO_REVOKE_TOKEN);
    }

    String tokenTypeHint = request.getParameter("token_type_hint");

    if (tokenTypeHint!=null && !OAuth2EnumMap.TOKEN_TYPE_MAP.containsKey(tokenTypeHint)) {
      throw new InvalidRequestException(ErrorCode.INVALID_TOKEN_TYPE);
    }
  }

}
