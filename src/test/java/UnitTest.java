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

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.oauth2.client.ClientDetailsService;
import com.google.googleidentity.oauth2.client.ClientSession;
import com.google.googleidentity.oauth2.client.InMemoryClientDetailsService;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;


public class UnitTest {

    /**
     * Test InMemoryUserDetailsService
     */
    @Test
    void testUserDetailsService() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertFalse(userDetailsService.getUserByName("111").isPresent());

        UserDetails user =
                UserDetails.newBuilder()
                        .setUsername("111")
                        .setPassword(Hashing.sha256()
                                .hashString("111", Charsets.UTF_8).toString())
                        .build();

        assertFalse(userDetailsService.updateUser(user));

        assertTrue(userDetailsService.addUser(user));

        assertTrue(userDetailsService.updateUser(user));

        assertFalse(userDetailsService.addUser(user));

    }

    /**
     * Test InMemoryClientDetailsService
     */
    @Test
    void testClientDetailsService() {
        ClientDetailsService clientDetailsService= new InMemoryClientDetailsService();

        assertFalse(clientDetailsService.getClientByID("111").isPresent());

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

        assertFalse(clientDetailsService.updateClient(client));

        assertTrue(clientDetailsService.addClient(client));

        assertTrue(clientDetailsService.updateClient(client));

        assertFalse(clientDetailsService.addClient(client));

    }

    /**
     * Test UserSession
     */
    @Test
    void testUserSession() {
        UserSession userSession= new UserSession();

        assertFalse(userSession.getUser().isPresent());

        UserDetails user =
                UserDetails.newBuilder()
                        .setUsername("111")
                        .setPassword(Hashing.sha256()
                                .hashString("111", Charsets.UTF_8).toString())
                        .build();


        userSession.setUser(user);

        assertTrue(userSession.getUser().isPresent());

    }


    /**
     * Test ClientSession
     */
    @Test
    void testClientSession() {
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
