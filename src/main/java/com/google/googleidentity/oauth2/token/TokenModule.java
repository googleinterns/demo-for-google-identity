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

package com.google.googleidentity.oauth2.token;

import com.google.inject.AbstractModule;

public class TokenModule extends AbstractModule {

  @Override
  protected void configure() {
    bind(OAuth2TokenService.class)
        .to(
            ("true").equals(System.getenv("USE_CLOUD_SQL"))
                ? JdbcOAuth2TokenService.class
                : InMemoryOAuth2TokenService.class);
  }
}
