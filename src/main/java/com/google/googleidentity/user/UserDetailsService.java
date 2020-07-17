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
import java.util.Optional;

/** UserDetailsService Interface. Support basic user information access and modification */
public interface UserDetailsService {

  /**
   * @return the user with the same username
   */
  Optional<UserDetails> getUserByName(String username);

  /**
   * Update the user with the same username, if the user does not exist, it will fail
   *
   * @return update success or not
   */
  boolean updateUser(UserDetails user);

  /**
   * Add user, if a user with same name exists, it will fail
   *
   * @return add success or not
   */
  boolean addUser(UserDetails user);

  /**
   * Get user by its email or google account id
   *
   * @return
   */
  Optional<UserDetails> getUserByEmailOrGoogleAccountId(String email, String gid);

  /** @return all users */
  List<UserDetails> listUser();

  void reset();
}
