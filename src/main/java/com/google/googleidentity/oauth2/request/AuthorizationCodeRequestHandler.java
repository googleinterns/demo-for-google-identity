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

package com.google.googleidentity.oauth2.request;

import com.google.googleidentity.oauth2.authorizationcode.AuthorizationCodeService;
import com.google.googleidentity.oauth2.exception.InvalidGrantException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Enums;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.inject.Inject;
import net.minidev.json.JSONObject;
import org.apache.http.client.utils.URIBuilder;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/** An Implementation of {@link RequestHandler}, handle request in Authorization Code Flow. */
final class AuthorizationCodeRequestHandler implements RequestHandler {

  private final AuthorizationCodeService authorizationCodeService;

  private final Logger log = Logger.getLogger("AuthorizationCodeRequestHandler");

  private final OAuth2TokenService oauth2TokenService;

  @Inject
  public AuthorizationCodeRequestHandler(
      AuthorizationCodeService authorizationCodeService, OAuth2TokenService oauth2TokenService) {
    this.authorizationCodeService = authorizationCodeService;
    this.oauth2TokenService = oauth2TokenService;
  }

  @Override
  public void handle(HttpServletResponse response, OAuth2Request oauth2Request)
      throws IOException, OAuth2Exception {
    if (oauth2Request.getRequestBody().getResponseType().equals(OAuth2Enums.ResponseType.CODE)) {
      String code = authorizationCodeService.getCodeForRequest(oauth2Request);

      try {
        URIBuilder uriBuilder =
            new URIBuilder(oauth2Request.getAuthorizationResponse().getRedirectUri())
                .addParameter(OAuth2ParameterNames.CODE, code);
        if (!oauth2Request.getAuthorizationResponse().getState().isEmpty()) {
          uriBuilder.addParameter(
              OAuth2ParameterNames.STATE, oauth2Request.getAuthorizationResponse().getState());
        }
        response.sendRedirect(uriBuilder.build().toString());
      } catch (URISyntaxException e) {
        log.log(Level.INFO, "Error when parse redirect uri to return auth code!", e);
      }

    } else if (oauth2Request
        .getRequestBody()
        .getResponseType()
        .equals(OAuth2Enums.ResponseType.TOKEN)) {
      Optional<OAuth2Request> opRequest =
          authorizationCodeService.consumeCode(oauth2Request.getRequestAuth().getCode());
      if (!opRequest.isPresent()) {
        throw new InvalidGrantException(InvalidGrantException.ErrorCode.NONEXISTENT_CODE);
      }
      if (!opRequest
          .get()
          .getRequestAuth()
          .getClientId()
          .equals(oauth2Request.getRequestAuth().getClientId())) {
        throw new InvalidGrantException(InvalidGrantException.ErrorCode.CODE_CLIENT_MISMATCH);
      }

      String redirectUri = oauth2Request.getAuthorizationResponse().getRedirectUri();

      if (!redirectUri.equals(opRequest.get().getAuthorizationResponse().getRedirectUri())) {
        throw new InvalidGrantException(InvalidGrantException.ErrorCode.CODE_REDIRECT_URI_MISMATCH);
      }

      OAuth2AccessToken token = oauth2TokenService.generateAccessToken(opRequest.get());

      JSONObject json = new JSONObject();

      json.appendField("token_type", "Bearer");
      json.appendField(OAuth2ParameterNames.ACCESS_TOKEN, token.getAccessToken());
      json.appendField(OAuth2ParameterNames.REFRESH_TOKEN, token.getRefreshToken());
      json.appendField("expires_in", token.getExpiredTime() - Instant.now().getEpochSecond());

      response.setContentType("application/json");

      response.getWriter().println(json.toJSONString());

      response.getWriter().flush();
    }
  }
}
