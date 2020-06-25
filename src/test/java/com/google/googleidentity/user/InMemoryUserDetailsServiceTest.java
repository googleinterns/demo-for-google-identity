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

package com.google.googleidentity.user;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static com.google.common.truth.Truth8.assertThat;

/**
 * Test {@link InMemoryUserDetailsService}
 */
public class InMemoryUserDetailsServiceTest {

    private static final String USERNAME = "111";
    private static final String PASSWORD = "111";

    private static final UserDetails USER =
            UserDetails.newBuilder()
                    .setUsername(USERNAME)
                    .setPassword(Hashing.sha256()
                            .hashString(PASSWORD, Charsets.UTF_8).toString())
                    .build();

    @Test
    void testUserDetailsService_updateNonExistedUser_fail() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertFalse(userDetailsService.updateUser(USER));

    }

    @Test
    void testUserDetailsService_getNonExistedUser_fail() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertFalse(userDetailsService.getUserByName("111").isPresent());

    }

    @Test
    void testUserDetailsService_addNonExistedUser_success() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertTrue(userDetailsService.addUser(USER));

    }

    @Test
    void testUserDetailsService_updateExistedUser_CorrectUpdate() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertTrue(userDetailsService.addUser(USER));

        UserDetails newUser = UserDetails.newBuilder(USER).setEmail("x@x.com").build();

        assertTrue(userDetailsService.updateUser(newUser));

        assertThat(userDetailsService.getUserByName(USERNAME)).hasValue(newUser);

    }

    @Test
    void testUserDetailsService_addExistedUser_fail() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertTrue(userDetailsService.addUser(USER));

        assertFalse(userDetailsService.addUser(USER));

    }

    @Test
    void testUserDetailsService_getExistedUser_success() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertTrue(userDetailsService.addUser(USER));

        assertTrue(userDetailsService.getUserByName("111").isPresent());

    }


}
