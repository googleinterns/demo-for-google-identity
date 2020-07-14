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

package com.google.googleidentity.oauth2.util;

/** OAuth2 constants like grant types and response types */
public final class OAuth2Constants {

  public static final class GrantType {
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String IMPLICIT = "implicit";
    public static final String JWT_ASSERTION = "urn:ietf:params:oauth:grant-type:jwt-bearer";
  }

  public static final class ResponseType {
    public static final String TOKEN = "token";
    public static final String CODE = "code";
  }

  public static final class JwtAssertionIntents {
    public static final String CHECK = "check";
    public static final String GET = "get";
    public static final String CREATE = "create";
  }

  public static final class TokenTypes {
    public static final String ACCESS_TOKEN = "access_token";
    public static final String REFRESH_TOKEN = "refresh_token";
  }
}
