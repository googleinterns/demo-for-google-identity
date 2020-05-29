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

import com.google.googleidentity.filter.UserAuthenticationFilter;
import com.google.googleidentity.oauth2.endpoint.AuthorizationEndpoint;
import com.google.googleidentity.oauth2.filter.ClientAuthenticationFilter;
import com.google.googleidentity.resource.UserServlet;
import com.google.googleidentity.security.LoginCheckServlet;
import com.google.googleidentity.security.LoginServlet;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.googleidentity.util.GeneralUtils;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;
import com.google.inject.servlet.ServletModule;

final class OAuth2Module extends AbstractModule {

    static final String TESTUSERNAME0 = "user";
    static final String TESTUSERPASSWORD0 = "123456";
    static final String TESTUSERNAME1 = "user1";
    static final String TESTUSERPASSWORD1 = "12345678";

    @Override
    protected void configure() {
        install(new ServletModule() {
            @Override
            protected void configureServlets() {
                serve("/resource/user",
                        "resource/user;jsessionid.*")
                        .with(UserServlet.class);
                // Support urlRewrite(with jsessionid)
                serveRegex("/login",
                        "/login;jsessionid.*")
                        .with(LoginServlet.class);
                serve("/login_check")
                        .with(LoginCheckServlet.class);
                serve("/oauth2/authorize")
                        .with(AuthorizationEndpoint.class);
                filterRegex("/oauth2/authorize",
                        "/resource/.*")
                        .through(UserAuthenticationFilter.class);
                filter("/oauth2/authorize")
                        .through(ClientAuthenticationFilter.class);
            }
        });
    }

    @Provides
    @Singleton
    UserDetailsService getUserDetailsService() {
        UserDetailsService userDetails = new InMemoryUserDetailsService();

        UserDetails.User user =
                UserDetails.User.newBuilder()
                        .setUsername(TESTUSERNAME0)
                        .setPassword(GeneralUtils.toHex(GeneralUtils.MD5(TESTUSERPASSWORD0)))
                        .build();

        userDetails.addUser(user);

        UserDetails.User user1 =
                UserDetails.User.newBuilder()
                        .setUsername(TESTUSERNAME1)
                        .setPassword(GeneralUtils.toHex(GeneralUtils.MD5(TESTUSERPASSWORD1)))
                        .build();

        userDetails.addUser(user1);

        return userDetails;
    }
}
