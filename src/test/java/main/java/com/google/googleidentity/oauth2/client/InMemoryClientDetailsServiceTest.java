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

package main.java.com.google.googleidentity.oauth2.client;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test InMemoryClientDetailsService
 */
public class InMemoryClientDetailsServiceTest {

    private static final ClientDetails client =
            ClientDetails.newBuilder()
                    .setClientId("111")
                    .setSecret(Hashing.sha256()
                            .hashString("111", Charsets.UTF_8).toString())
                    .addScope("read")
                    .setIsScoped(true)
                    .addGrantTypes("authorization")
                    .setRedirectUri("http://localhost:8080/redirect")
                    .build();


    @Test
    void testClientDetailsService_updateNonExistUser_fail() {
        ClientDetailsService clientDetailsService= new InMemoryClientDetailsService();

        assertFalse(clientDetailsService.updateClient(client));

    }

    @Test
    void testClientDetailsService_getNonExistUser_notPresent() {
        ClientDetailsService clientDetailsService= new InMemoryClientDetailsService();

        assertFalse(clientDetailsService.getClientByID("111").isPresent());
    }

    @Test
    void testClientDetailsService_addNonExistUser_success() {
        ClientDetailsService clientDetailsService= new InMemoryClientDetailsService();

        assertTrue(clientDetailsService.addClient(client));
    }

    @Test
    void testClientDetailsService_updateExistUser_success() {
        ClientDetailsService clientDetailsService= new InMemoryClientDetailsService();

        assertTrue(clientDetailsService.addClient(client));

        assertTrue(clientDetailsService.updateClient(client));
    }

    @Test
    void testClientDetailsService_addExistUser_fail() {
        ClientDetailsService clientDetailsService= new InMemoryClientDetailsService();

        assertTrue(clientDetailsService.addClient(client));

        assertFalse(clientDetailsService.addClient(client));

    }

    @Test
    void testClientDetailsService_getExistUser_success() {
        ClientDetailsService clientDetailsService= new InMemoryClientDetailsService();

        assertTrue(clientDetailsService.addClient(client));

        assertTrue(clientDetailsService.getClientByID("111").isPresent());

    }


}
