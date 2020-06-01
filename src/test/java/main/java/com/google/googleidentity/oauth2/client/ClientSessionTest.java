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
import com.google.googleidentity.oauth2.client.ClientSession;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test ClientSession
 */
public class ClientSessionTest {


    @Test
    void testClientSession_correctInsertion_canReadOut() {
        ClientSession clientSession= new ClientSession();

        assertFalse(clientSession.getClient().isPresent());

        ClientDetails client =
                ClientDetails.newBuilder()
                        .setClientId("111")
                        .setSecret(Hashing.sha256()
                                .hashString("111", Charsets.UTF_8).toString())
                        .addScope("read")
                        .setIsScoped(true)
                        .addGrantTypes("authorization")
                        .setRedirectUri("http://localhost:8080/redirect")
                        .build();

        clientSession.setClient(client);

        assertTrue(clientSession.getClient().isPresent());

    }
}
