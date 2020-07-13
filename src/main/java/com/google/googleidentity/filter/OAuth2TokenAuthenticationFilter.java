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

package com.google.googleidentity.filter;

import com.google.common.base.Strings;
import com.google.googleidentity.oauth2.token.OAuth2AccessToken;
import com.google.googleidentity.oauth2.token.OAuth2TokenService;
import com.google.googleidentity.oauth2.util.OAuth2ParameterNames;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import javax.servlet.Filter;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.Instant;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * The filter to protect resources using oauth2 token. It is set before {@link
 * UserAuthenticationFilter}. If the token is valid, {@link UserSession} will be set. Therefore,
 * {@link UserAuthenticationFilter} will be passed.
 */
@Singleton
public class OAuth2TokenAuthenticationFilter implements Filter {

  private static final long serialVersionUID = 9L;

  private static final Logger log = Logger.getLogger("UserAuthenticationFilter");

  private final UserDetailsService userDetailsService;

  private final OAuth2TokenService oauth2TokenService;

  @Inject
  public OAuth2TokenAuthenticationFilter(
      UserDetailsService userDetailsService, OAuth2TokenService oauth2TokenService) {
    this.userDetailsService = userDetailsService;
    this.oauth2TokenService = oauth2TokenService;
  }

  public void init(FilterConfig filterConfig) throws ServletException {}

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
      throws IOException, ServletException {

    String accessToken = request.getParameter(OAuth2ParameterNames.ACCESS_TOKEN);

    // Check token and set related user authentication session
    if (!Strings.isNullOrEmpty(accessToken)) {
      Optional<OAuth2AccessToken> token = oauth2TokenService.readAccessToken(accessToken);
      if (token.isPresent()
          && Instant.ofEpochSecond(token.get().getExpiredTime()).isAfter(Instant.now())) {
        UserSession userSession = OAuth2Utils.getUserSession((HttpServletRequest) request);
        userSession.setUser(userDetailsService.getUserByName(token.get().getUsername()).get());
        OAuth2Utils.setUserSession((HttpServletRequest) request, userSession);
      }
    }
    chain.doFilter(request, response);
  }

  public void destroy() {}
}
