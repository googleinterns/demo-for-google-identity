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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

//default userdetails service
public class InMemoryUserDetailsService implements UserDetailsService{

    private ConcurrentHashMap<String, UserDetails>  userStore = new ConcurrentHashMap<String, UserDetails>();

    public UserDetails getUserById(String username) {
        return null;
    }

    public void updateUser(UserDetails user) {
        if(user == null){
            throw new RuntimeException("No User!");
        }
        String username = user.getUsername();
        if(username == null){
            throw new RuntimeException("No Username!");
        }
        if(!userStore.containsKey(username)){
            throw new RuntimeException("No User Named" + username);
        }
        userStore.put(username, user);
    }

    public List<UserDetails> listUser() {
        return new ArrayList<UserDetails>(userStore.values());
    }
}
