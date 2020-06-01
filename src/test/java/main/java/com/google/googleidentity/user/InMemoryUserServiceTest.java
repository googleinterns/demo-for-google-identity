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

package main.java.com.google.googleidentity.user;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.googleidentity.user.InMemoryUserDetailsService;
import com.google.googleidentity.user.UserDetails;
import com.google.googleidentity.user.UserDetailsService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test {@link InMemoryUserDetailsService}
 */
public class InMemoryUserServiceTest {

    UserDetails user =
            UserDetails.newBuilder()
                    .setUsername("111")
                    .setPassword(Hashing.sha256()
                            .hashString("111", Charsets.UTF_8).toString())
                    .build();

    @Test
    void testUserDetailsService_updateNonExistedUser_fail() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertFalse(userDetailsService.updateUser(user));

    }

    @Test
    void testUserDetailsService_getNonExistedUser_fail() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertFalse(userDetailsService.getUserByName("111").isPresent());

    }

    @Test
    void testUserDetailsService_addNonExistedUser_success() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertTrue(userDetailsService.addUser(user));

    }

    @Test
    void testUserDetailsService_updateExistedUser_success() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertTrue(userDetailsService.addUser(user));

        assertTrue(userDetailsService.updateUser(user));

    }

    @Test
    void testUserDetailsService_addExistedUser_fail() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertTrue(userDetailsService.addUser(user));

        assertFalse(userDetailsService.addUser(user));

    }

    @Test
    void testUserDetailsService_getExistedUser_success() {
        UserDetailsService userDetailsService= new InMemoryUserDetailsService();

        assertTrue(userDetailsService.addUser(user));

        assertTrue(userDetailsService.getUserByName("111").isPresent());

    }


}
