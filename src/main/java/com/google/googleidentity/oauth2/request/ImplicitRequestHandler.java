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

import com.google.common.base.Strings;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.OAuth2ServerException;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.inject.Inject;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletResponse;
import org.apache.http.client.utils.URIBuilder;

final class ImplicitRequestHandler implements RequestHandler {

  private static final Logger log = Logger.getLogger("ImplicitRequestHandler");
  private final OAuth2TokenService oauth2TokenService;

  @Inject
  public ImplicitRequestHandler(OAuth2TokenService oauth2TokenService) {
    this.oauth2TokenService = oauth2TokenService;
  }

  @Override
  public void handle(HttpServletResponse response, OAuth2Request oauth2Request)
      throws IOException, OAuth2Exception {
    OAuth2AccessToken token = oauth2TokenService.generateAccessToken(oauth2Request);

    try {
      URIBuilder uriBuilder =
          new URIBuilder(oauth2Request.getAuthorizationResponse().getRedirectUri())
              .addParameter(OAuth2ParameterNames.ACCESS_TOKEN, token.getAccessToken())
              .addParameter("token_type", "bearer");
      if (!Strings.isNullOrEmpty(oauth2Request.getAuthorizationResponse().getState())) {
        uriBuilder.addParameter(
            OAuth2ParameterNames.STATE, oauth2Request.getAuthorizationResponse().getState());
      }
      response.sendRedirect(uriBuilder.build().toString());
    } catch (URISyntaxException e) {
      throw new OAuth2ServerException("Error when parsing response url for implicit flow.", e);
    }
  }
}
