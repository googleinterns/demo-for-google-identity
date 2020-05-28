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

import com.google.googleidentity.security.LoginCheckServlet;
import com.google.googleidentity.security.LoginServlet;
import com.google.googleidentity.filter.UserAuthenticationFilter;
import com.google.googleidentity.resource.UserServlet;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.googleidentity.util.OAuth2Utils;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;
import com.google.inject.servlet.ServletModule;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

class OAuth2Module extends AbstractModule {



    @Override
    protected void configure(){
        install(new ServletModule() {
            @Override
            protected void configureServlets(){
                serve("/resource/user", "resource/user;jsessionid.*").with(UserServlet.class);
                //support urlRewrite(with jsessionid)
                serveRegex("/login", "/login;jsessionid.*").with(LoginServlet.class);
                serve("/login_check").with(LoginCheckServlet.class);
                filterRegex("/oauth2/authorize",  "/resource/.*").through(UserAuthenticationFilter.class);
            }
        });
    }

    @Provides
    @Singleton
    UserDetailsService getUserDetailsService(){
        UserDetailsService userDetails = new InMemoryUserDetailsService();

        UserDetails.User user =
                UserDetails.User.newBuilder()
                        .setUsername("user")
                        .setPassword(OAuth2Utils.MD5("123456"))
                        .build();

        userDetails.addUser(user);

        UserDetails.User user1 =
                UserDetails.User.newBuilder()
                        .setUsername("user1")
                        .setPassword(OAuth2Utils.MD5("12345678"))
                        .build();

        userDetails.addUser(user1);

        return userDetails;
    }
}
