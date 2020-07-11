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

package com.google.googleidentity.user.test;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.inject.Singleton;

public class TestUserModule extends AbstractModule {

  private static final String TESTUSERNAME0 = "user";
  private static final String TESTUSERPASSWORD0 = "123456";
  private static final String TESTUSERNAME1 = "user1";
  private static final String TESTUSERPASSWORD1 = "12345678";

  @Override
  protected void configure() {}

  @Provides
  @Singleton
  public UserDetailsService getUserDetailsService(InMemoryUserDetailsService userDetailsService) {
    UserDetails user =
        UserDetails.newBuilder()
            .setUsername(TESTUSERNAME0)
            .setPassword(Hashing.sha256().hashString(TESTUSERPASSWORD0, Charsets.UTF_8).toString())
            .build();

    userDetailsService.addUser(user);

    UserDetails user1 =
        UserDetails.newBuilder()
            .setUsername(TESTUSERNAME1)
            .setPassword(Hashing.sha256().hashString(TESTUSERPASSWORD1, Charsets.UTF_8).toString())
            .build();
    return userDetailsService;
  }
}
