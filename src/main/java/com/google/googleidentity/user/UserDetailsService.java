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

import java.util.List;

/**
 * UserDetailsService Interface.
 * Support basic user information access and modification
 */
public interface UserDetailsService {

    /**
     * @param username usernmae
     * @return the user with the same username
     */
    UserDetails.User getUserByName(String username);

    /**
     * @param user new user information
     * @return update success or not
     */
    boolean updateUser(UserDetails.User user);

    /**
     * @param user new user information
     * @return add success or not
     */
    boolean addUser(UserDetails.User user);

    /**
     * @return all users
     */
    List<UserDetails.User> listUser();

}

