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
import com.google.common.base.Strings;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.InvalidRequestException.ErrorCode;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2Constants.TokenTypes;
import com.google.googleidentity.oauth2.util.OAuth2EnumMap;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.oauth2.validator.TokenRevokeEndpointRequestValidator;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import java.io.IOException;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;

@Singleton
public class UserInfoEndpoint extends HttpServlet {

  private static final long serialVersionUID = 5L;

  private static final Logger log = Logger.getLogger("TokenEndpoint");

  private final UserDetailsService userDetailsService;

  private final OAuth2TokenService oauth2TokenService;

  @Inject
  public UserInfoEndpoint(
      UserDetailsService userDetailsService, OAuth2TokenService oauth2TokenService) {
    this.userDetailsService = userDetailsService;
    this.oauth2TokenService = oauth2TokenService;
  }

  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException, UnsupportedOperationException {
      String accessToken = request.getParameter(OAuth2ParameterNames.ACCESS_TOKEN);

    try {
      if (Strings.isNullOrEmpty(accessToken)) {
          throw new InvalidRequestException(ErrorCode.NO_ACCESS_TOKEN);
      }

      if (!oauth2TokenService.readAccessToken(accessToken).isPresent()) {
        throw new InvalidRequestException(ErrorCode.INVALID_ACCESS_TOKEN);
      }

      UserDetails user = userDetailsService.getUserByName(oauth2TokenService.readAccessToken(accessToken).get().getUsername()).get();
      JSONObject json = new JSONObject();
      json.appendField("username", user.getUsername());
      json.appendField("email", user.getEmail());
      json.appendField("google_account_id", user.getGoogleAccountId());

      response.getWriter().println(json.toJSONString());
      response.getWriter().flush();
    } catch (OAuth2Exception exception) {
      log.info(
          "Failed when process request in User Info Endpoint"
              + "Error Type: "
              + exception.getErrorType()
              + "Description: "
              + exception.getErrorDescription());
      OAuth2ExceptionHandler.handle(exception, response);
      return;
    }
  }
  }
