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

package com.google.googleidentity.oauth2.validator;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.exception.InvalidRequestException;
import com.google.googleidentity.oauth2.exception.OAuth2Exception;
import com.google.googleidentity.oauth2.util.OAuth2Constants;
import com.google.googleidentity.oauth2.util.OAuth2Constants.TokenTypes;
import com.google.googleidentity.oauth2.util.OAuth2Enums.GrantType;
import com.google.googleidentity.testtools.FakeHttpSession;
import javax.servlet.http.HttpServletRequest;
import org.junit.Test;

public class TokenRevokeEndpointRequestValidatorTest {
  private static final String CLIENTID = "client";
  private static final String SECRET = "111";
  private static final String REDIRECT_URI = "http://www.google.com";
  private static final String LINE = System.lineSeparator();
  private static final ImmutableList<GrantType> TESTGRANTTYPES =
      ImmutableList.of(
          GrantType.AUTHORIZATION_CODE,
          GrantType.IMPLICIT,
          GrantType.REFRESH_TOKEN,
          GrantType.JWT_ASSERTION);
  private static final ClientDetails CLIENT =
      ClientDetails.newBuilder()
          .setClientId(CLIENTID)
          .setSecret(Hashing.sha256().hashString(SECRET, Charsets.UTF_8).toString())
          .addScopes("read")
          .setIsScoped(true)
          .addRedirectUris(REDIRECT_URI)
          .addAllGrantTypes(TESTGRANTTYPES)
          .build();

  @Test
  public void test_validatePost_noToken_throwInvalidRequestException() {

    HttpServletRequest request = mock(HttpServletRequest.class);
    FakeHttpSession httpSession = new FakeHttpSession();

    when(request.getParameter("token")).thenReturn(null);
    when(request.getParameter("token_type_hint")).thenReturn(TokenTypes.ACCESS_TOKEN);

    OAuth2Exception e =
        assertThrows(
            OAuth2Exception.class, () -> TokenRevokeEndpointRequestValidator.validatePOST(request));

    assertThat(e).isInstanceOf(InvalidRequestException.class);

    assertThat(e.getErrorDescription()).isEqualTo("No token to revoke!");
  }

  @Test
  public void test_validatePost_invalidTokenType_throwInvalidRequestException() {

    HttpServletRequest request = mock(HttpServletRequest.class);
    FakeHttpSession httpSession = new FakeHttpSession();

    when(request.getParameter("token")).thenReturn("token");
    when(request.getParameter("token_type_hint")).thenReturn("invalid");

    OAuth2Exception e =
        assertThrows(
            OAuth2Exception.class, () -> TokenRevokeEndpointRequestValidator.validatePOST(request));

    assertThat(e).isInstanceOf(InvalidRequestException.class);

    assertThat(e.getErrorDescription()).isEqualTo("Invalid token type!");
  }

  @Test
  public void test_validatePost_correctRequest_throwNoException() {

    HttpServletRequest request = mock(HttpServletRequest.class);
    FakeHttpSession httpSession = new FakeHttpSession();

    when(request.getParameter("token")).thenReturn("token");
    when(request.getParameter("token_type_hint")).thenReturn(TokenTypes.ACCESS_TOKEN);

    assertDoesNotThrow(() -> TokenRevokeEndpointRequestValidator.validatePOST(request));
  }
}
