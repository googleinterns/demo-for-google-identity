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

import com.google.common.base.Preconditions;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default InMemory UserDetailsService for user information Store.
 */
public class InMemoryUserDetailsService implements UserDetailsService {

    private ConcurrentHashMap<String, UserDetails.User> userStore
            = new ConcurrentHashMap<>();

    public UserDetails.User getUserByName(String username) {

        return userStore.getOrDefault(username, null);
    }

    public boolean updateUser(UserDetails.User user) {

        Preconditions.checkNotNull(user);

        String username = user.getUsername();
        if (username == null) {
            return false;
        }
        if (!userStore.containsKey(username)) {
            return false;
        }
        userStore.put(username, user);
        return true;
    }

    @Override
    public boolean addUser(UserDetails.User user) {

        Preconditions.checkNotNull(user);

        String username = user.getUsername();
        if (username == null) {
            return false;
        }
        if (userStore.containsKey(username)) {
            return false;
        }
        userStore.put(username, user);
        return true;
    }

    public List<UserDetails.User> listUser() {
        return new ArrayList<UserDetails.User>(userStore.values());
    }
}

