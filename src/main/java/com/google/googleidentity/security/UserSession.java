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

package com.google.googleidentity.security;

import com.google.googleidentity.oauth2.client.ClientDetails;
import com.google.googleidentity.user.UserDetails;

import java.io.Serializable;
import java.util.Optional;

/**
 * UserSession Object Store a logged in user's information in {@link
 * com.google.googleidentity.user.UserDetails} Object. Store an original request that filtered by
 * {@link com.google.googleidentity.filter.UserAuthenticationFilter}. Stored in HttpSession named
 * user_session
 */
public final class UserSession implements Serializable {

  private static final long serialVersionUID = 3L;

  private UserDetails user = null;

  private ClientDetails client = null;

  private String olduri = null;

  public Optional<UserDetails> getUser() {
    return Optional.ofNullable(user);
  }

  public void setUser(UserDetails user) {
    this.user = user;
  }

  public Optional<ClientDetails> getClient() {
    return Optional.ofNullable(client);
  }

  public void setClient(ClientDetails client) {
    this.client = client;
  }

  public Optional<String> getOlduri() {
    return Optional.ofNullable(olduri);
  }

  public void setOlduri(String olduri) {
    this.olduri = olduri;
  }

  @Override
  public String toString() {

    StringBuilder sb = new StringBuilder();
    if (user != null) {
      sb.append("user:").append(user.toString()).append("\t");
    }

    if (client != null) {
      sb.append("client:").append(client.toString()).append("\t");
    }

    if (olduri != null) {
      sb.append("olduri:").append(olduri).append("\t");
    }
    return sb.toString();
  }
}
