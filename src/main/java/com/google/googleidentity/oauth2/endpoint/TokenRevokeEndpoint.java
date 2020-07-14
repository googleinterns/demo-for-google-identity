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
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidGrantException;
import com.google.googleidentity.oauth2.exception.InvalidGrantException.ErrorCode;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2RefreshToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Constants.TokenTypes;
import com.google.googleidentity.oauth2.util.OAuth2EnumMap;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.oauth2.validator.TokenRevokeEndpointRequestValidator;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.util.Optional;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;

@Singleton
public class TokenRevokeEndpoint extends HttpServlet {

  private static final long serialVersionUID = 5L;

  private static final Logger log = Logger.getLogger("TokenEndpoint");

  private final ClientDetailsService clientDetailsService;

  private final OAuth2TokenService oauth2TokenService;

  @Inject
  public TokenRevokeEndpoint(
      ClientDetailsService clientDetailsService, OAuth2TokenService oauth2TokenService) {
    this.clientDetailsService = clientDetailsService;
    this.oauth2TokenService = oauth2TokenService;
  }

  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException, UnsupportedOperationException {
    OAuth2Exception exception =
        new InvalidRequestException(InvalidRequestException.ErrorCode.UNSUPPORTED_REQUEST_METHOD);
    log.info("Token Revoke endpoint does not support GET request.");
    OAuth2ExceptionHandler.handle(exception, response);
    return;
  }

  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException, UnsupportedOperationException {

    try {
      TokenRevokeEndpointRequestValidator.validatePOST(request);
    } catch (OAuth2Exception exception) {
      log.info(
          "Failed in validating Post request in Token Revoke Endpoint."
              + "Error Type: "
              + exception.getErrorType()
              + "Description: "
              + exception.getErrorDescription());
      OAuth2ExceptionHandler.handle(exception, response);
      return;
    }

    Preconditions.checkArgument(
        OAuth2Utils.getClientSession(request).getClient().isPresent(),
        "Client should have been set in client filter!");
    ClientDetails client = OAuth2Utils.getClientSession(request).getClient().get();

    String tokenTypeHint = request.getParameter("token_type_hint");

    if (tokenTypeHint == null) {
      tokenTypeHint = TokenTypes.ACCESS_TOKEN;
    }
    OAuth2Request.Builder builder = OAuth2Request.newBuilder();
    builder.getRequestAuthBuilder().setClientId(client.getClientId());
    builder
        .getRequestBodyBuilder()
        .setTokenToRevoke(request.getParameter("token"))
        .setTokenTypeHint(OAuth2EnumMap.TOKEN_TYPE_MAP.get(tokenTypeHint));
    try {
      revokeToken(response, builder.build());
    } catch (OAuth2Exception exception) {
      log.info(
          "Failed when process request in Token Revoke Endpoint"
              + "Error Type: "
              + exception.getErrorType()
              + "Description: "
              + exception.getErrorDescription());
      OAuth2ExceptionHandler.handle(exception, response);
      return;
    }
    JSONObject json = new JSONObject();
    response.setContentType("application/json;charset=UTF-8");
    response.getWriter().println(json.toJSONString());
    response.getWriter().flush();
  }

  public void revokeToken(HttpServletResponse response, OAuth2Request request)
      throws InvalidGrantException {
    String token = request.getRequestBody().getTokenToRevoke();

    switch (request.getRequestBody().getTokenTypeHint()) {
      case ACCESS:
        Optional<OAuth2AccessToken> oldAccessToken = oauth2TokenService.readAccessToken(token);
        if (!oldAccessToken.isPresent()) {
          throw new InvalidGrantException(ErrorCode.NONEXISTENT_REVOKE_TOKEN);
        } else if (!oldAccessToken
            .get()
            .getClientId()
            .equals(request.getRequestAuth().getClientId())) {
          throw new InvalidGrantException(ErrorCode.REVOKE_TOKEN_CLIENT_MISMATCH);
        }
        oauth2TokenService.revokeByAccessToken(token);
        break;
      case REFRESH:
        Optional<OAuth2RefreshToken> oldRefreshToken = oauth2TokenService.readRefreshToken(token);
        if (!oldRefreshToken.isPresent()) {
          throw new InvalidGrantException(ErrorCode.NONEXISTENT_REVOKE_TOKEN);
        } else if (!oldRefreshToken
            .get()
            .getClientId()
            .equals(request.getRequestAuth().getClientId())) {
          throw new InvalidGrantException(ErrorCode.REVOKE_TOKEN_CLIENT_MISMATCH);
        }
        oauth2TokenService.revokeByRefreshToken(token);
        break;
      default:
        throw new IllegalStateException();
    }
  }
}
