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

import com.google.common.collect.ImmutableMap;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.oauth2.util.OAuth2Enums.ResponseType;

public class OAuth2EnumMap {
  public static final ImmutableMap<String, ResponseType> RESPONSE_TYPE_MAP =
      ImmutableMap.of(
          OAuth2Constants.ResponseType.CODE, ResponseType.CODE,
          OAuth2Constants.ResponseType.TOKEN, ResponseType.TOKEN);

  public static final ImmutableMap<String, GrantType> GRANT_TYPE_MAP =
      ImmutableMap.of(
          OAuth2Constants.GrantType.AUTHORIZATION_CODE, GrantType.AUTHORIZATION_CODE,
          OAuth2Constants.GrantType.IMPLICIT, GrantType.IMPLICIT,
          OAuth2Constants.GrantType.REFRESH_TOKEN, GrantType.REFRESH_TOKEN,
          OAuth2Constants.GrantType.JWT_ASSERTION, GrantType.JWT_ASSERTION);
}
