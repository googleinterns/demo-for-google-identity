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

package com.google.googleidentity.oauth2.refresh;

import com.google.googleidentity.oauth2.exception.InvalidGrantException;
import com.google.googleidentity.oauth2.exception.InvalidGrantException.ErrorCode;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.request.RequestHandler;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2RefreshToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.inject.Inject;
import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import javax.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;

/** TokenProcessor for refresh token request */
public class RefreshTokenRequestHandler implements RequestHandler {

  private final OAuth2TokenService oauth2TokenService;

  @Inject
  public RefreshTokenRequestHandler(OAuth2TokenService oauth2TokenService) {
    this.oauth2TokenService = oauth2TokenService;
  }

  @Override
  public void handle(HttpServletResponse response, OAuth2Request oauth2Request)
      throws IOException, OAuth2Exception {

    Optional<OAuth2RefreshToken> oldToken =
        oauth2TokenService.readRefreshToken(oauth2Request.getRequestBody().getRefreshToken());

    if (!oldToken.isPresent()) {
      throw new InvalidGrantException(ErrorCode.NONEXISTENT_REFRESH_TOKEN);
    }

    if (!oldToken.get().getClientId().equals(oauth2Request.getRequestAuth().getClientId())) {
      throw new InvalidGrantException(ErrorCode.REFRESH_TOKEN_CLIENT_MISMATCH);
    }

    Optional<OAuth2AccessToken> newToken =
        oauth2TokenService.refreshToken(oauth2Request.getRequestBody().getRefreshToken());

    JSONObject json = new JSONObject();

    json.appendField("token_type", "Bearer");
    json.appendField(OAuth2ParameterNames.ACCESS_TOKEN, newToken.get().getAccessToken());
    json.appendField(
        "expires_in", newToken.get().getExpiredTime() - Instant.now().getEpochSecond());

    response.setContentType("application/json");

    response.getWriter().println(json.toJSONString());

    response.getWriter().flush();
  }
}
