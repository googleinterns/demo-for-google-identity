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

package com.google.googleidentity.oauth2.client;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static com.google.common.truth.Truth8.assertThat;

/** Test {@link InMemoryClientDetailsService} */
public class InMemoryClientDetailsServiceTest {

  private static final String CLIENTID = "client";
  private static final String SECRET = "111";

  private static final ClientDetails CLIENT =
      ClientDetails.newBuilder()
          .setClientId(CLIENTID)
          .setSecret(Hashing.sha256().hashString(SECRET, Charsets.UTF_8).toString())
          .addScopes("read")
          .setIsScoped(true)
          .build();

  @Test
  void testClientDetailsService_updateNonExistClient_fail() {
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    assertFalse(clientDetailsService.updateClient(CLIENT));
  }

  @Test
  void testClientDetailsService_getNonExistUser_notPresent() {
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    assertFalse(clientDetailsService.getClientByID(CLIENTID).isPresent());
  }

  @Test
  void testClientDetailsService_addNonExistUser_success() {
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    assertTrue(clientDetailsService.addClient(CLIENT));
  }

  @Test
  void testClientDetailsService_updateExistUser_CorrectUpdate() {
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    assertTrue(clientDetailsService.addClient(CLIENT));

    ClientDetails newClient = ClientDetails.newBuilder(CLIENT).setIsScoped(false).build();

    assertTrue(clientDetailsService.updateClient(newClient));

    assertThat(clientDetailsService.getClientByID(CLIENTID)).hasValue(newClient);
  }

  @Test
  void testClientDetailsService_addExistUser_fail() {
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    assertTrue(clientDetailsService.addClient(CLIENT));

    assertFalse(clientDetailsService.addClient(CLIENT));
  }

  @Test
  void testClientDetailsService_getExistUser_success() {
    ClientDetailsService clientDetailsService = new InMemoryClientDetailsService();

    assertTrue(clientDetailsService.addClient(CLIENT));

    assertTrue(clientDetailsService.getClientByID(CLIENTID).isPresent());
  }
}
