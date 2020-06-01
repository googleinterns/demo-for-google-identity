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

package main.java.com.google.googleidentity.security;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.security.UserSession;
import com.google.googleidentity.user.UserDetails;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test UserSession
 */
public class UserSessionTest {


    @Test
    void testUserSession_correctInsertion_canReadOut() {
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
}
