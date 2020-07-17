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

package com.google.googleidentity.config;

import com.google.googleidentity.filter.ClientLoginFilter;
import com.google.googleidentity.filter.OAuth2TokenAuthenticationFilter;
import com.google.googleidentity.filter.UserAuthenticationFilter;
import com.google.googleidentity.oauth2.endpoint.AuthorizationEndpoint;
import com.google.googleidentity.oauth2.endpoint.ConsentEndpoint;
import com.google.googleidentity.oauth2.endpoint.JwkEndpoint;
import com.google.googleidentity.oauth2.endpoint.RiscDocEndpoint;
import com.google.googleidentity.oauth2.endpoint.UnlinkEndpoint;
import com.google.googleidentity.oauth2.endpoint.TokenEndpoint;
import com.google.googleidentity.oauth2.endpoint.TokenRevokeEndpoint;
import com.google.googleidentity.oauth2.endpoint.UserInfoEndpoint;
import com.google.googleidentity.oauth2.filter.ClientAuthenticationFilter;
import com.google.googleidentity.resource.ChangeSettingServlet;
import com.google.googleidentity.resource.ClientServlet;
import com.google.googleidentity.resource.LogoutServlet;
import com.google.googleidentity.resource.UnlinkServlet;
import com.google.googleidentity.resource.UserServlet;
import com.google.googleidentity.resource.ViewTokensServlet;
import com.google.googleidentity.security.ChangePasswordServlet;
import com.google.googleidentity.security.ClientLoginCheckServlet;
import com.google.googleidentity.security.ClientRegisterCheckServlet;
import com.google.googleidentity.security.ClientRegisterServlet;
import com.google.googleidentity.security.LoginCheckServlet;
import com.google.googleidentity.security.LoginServlet;
import com.google.googleidentity.security.RegisterCheckServlet;
import com.google.googleidentity.security.RegisterServlet;
import com.google.inject.AbstractModule;
import com.google.inject.servlet.ServletModule;

public final class OAuth2Module extends AbstractModule {

  @Override
  protected void configure() {
    install(
        new ServletModule() {
          @Override
          protected void configureServlets() {
            serveRegex("/resource/user", "resource/user;jsessionid.*").with(UserServlet.class);
            serveRegex("/", "/login", "/login;jsessionid.*").with(LoginServlet.class);
            serveRegex("/login_check", "/login_check;jsessionid.*").with(LoginCheckServlet.class);
            serveRegex("/register", "/register;jsessionid.*").with(RegisterServlet.class);
            serveRegex("/register_check", "/register_check;jsessionid.*")
                .with(RegisterCheckServlet.class);
            serve("/resource/user/change_password").with(ChangePasswordServlet.class);
            serve("/resource/user/view_tokens").with(ViewTokensServlet.class);
            serve("/resource/user/unlink").with(UnlinkServlet.class);
            serve("/resource/user/logout").with(LogoutServlet.class);
            serve("/client_login_check").with(ClientLoginCheckServlet.class);
            serve("/register_client").with(ClientRegisterServlet.class);
            serve("/client_register_check").with(ClientRegisterCheckServlet.class);
            serve("/client").with(ClientServlet.class);
            serve("/client/change_setting").with(ChangeSettingServlet.class);
            serve("/oauth2/authorize").with(AuthorizationEndpoint.class);
            serve("/oauth2/consent").with(ConsentEndpoint.class);
            serve("/oauth2/token").with(TokenEndpoint.class);
            serve("/oauth2/revoke").with(TokenRevokeEndpoint.class);
            serve("/oauth2/userinfo").with(UserInfoEndpoint.class);
            serve("/oauth2/risc/.well-known/risc-configuration").with(RiscDocEndpoint.class);
            serve("/oauth2/risc/key").with(JwkEndpoint.class);
            serve("/oauth2/unlink").with(UnlinkEndpoint.class);
            // The filter order is same as the order they be introduced here, let token
            // authentication filter be at the first so that it can set client session from token to
            // let the request pass user authentication filter
            filterRegex("/client","/client/.*").through(ClientLoginFilter.class);
            filterRegex("/resource/.*").through(OAuth2TokenAuthenticationFilter.class);
            filterRegex("/oauth2/authorize", "/resource/.*")
                .through(UserAuthenticationFilter.class);
            filter("/oauth2/token", "/oauth2/revoke")
                .through(ClientAuthenticationFilter.class);
          }
        });
  }
}
