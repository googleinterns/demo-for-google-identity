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

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

/** Test functions in {@link OAuth2Utils} */
public class OAuth2UtilsTest {

  @Test
  void testParseScope_nullOrEmptyInput_EmptyOut() {

    Set<String> scopes = OAuth2Utils.parseScope(null);

    assertTrue(scopes.isEmpty());

    scopes = OAuth2Utils.parseScope("   ");

    assertTrue(scopes.isEmpty());
  }

  @Test
  void testParseScope_validInput_CorrectOut() {

    Set<String> scopes = OAuth2Utils.parseScope("read write  modify");

    assertThat(scopes).containsExactly("read", "write", "modify");
  }

  @Test
  void testMatchUri_simpleGALCorrectInput_CorrectOut() {
    assertTrue(
        OAuth2Utils.matchUri(
            ImmutableList.of("https://oauth-redirect.googleusercontent.com/r/"),
            "https://oauth-redirect.googleusercontent.com/r/YOUR_PROJECT_ID"));
  }

  @Test
  void testMatchUri_simpleGALWrongInput_ReturnFalse() {
    assertFalse(
        OAuth2Utils.matchUri(
            ImmutableList.of("https://oauth-redirect.googleusercontent.com/r/"), "wrong_uri"));
  }
}
