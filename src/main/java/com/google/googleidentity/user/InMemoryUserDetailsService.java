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
import com.google.common.collect.ImmutableList;
import com.google.inject.Singleton;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default InMemory UserDetailsService for user information Store.
 */
@Singleton
public final class InMemoryUserDetailsService implements UserDetailsService {

    private final ConcurrentHashMap<String, UserDetails> userStore =
            new ConcurrentHashMap<>();

    public Optional<UserDetails> getUserByName(String username) {

        return Optional.ofNullable(userStore.get(username));
    }

    public boolean updateUser(UserDetails user) {

        Preconditions.checkNotNull(user);

        String username = user.getUsername();
        if (username.isEmpty()) {
            throw new IllegalArgumentException("Empty username");
        }
        if (!userStore.containsKey(username)) {
            return false;
        }
        userStore.put(username, user);
        return true;
    }

    @Override
    public boolean addUser(UserDetails user) {

        Preconditions.checkNotNull(user);

        String username = user.getUsername();
        if (username.isEmpty()) {
            throw new IllegalArgumentException("Empty username");
        }
        if (userStore.containsKey(username)) {
            return false;
        }
        userStore.put(username, user);
        return true;
    }

    public List<UserDetails> listUser() {
        return ImmutableList.copyOf(userStore.values());
    }
}
