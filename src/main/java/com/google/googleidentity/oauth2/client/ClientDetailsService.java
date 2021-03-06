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

package com.google.googleidentity.oauth2.client;

import java.util.List;
import java.util.Optional;

/** ClientDetailsService Interface. Support basic client information access and modification */
public interface ClientDetailsService {

  /**
   * @param clientID the clientID
   * @return the client information with the clientID
   */
  Optional<ClientDetails> getClientByID(String clientID);

  /**
   * update a client's information, fail if no client match the clientID
   *
   * @param client new Client Information
   * @return update success or not
   */
  boolean updateClient(ClientDetails client);

  /**
   * Add a new client's information, fail if there is already a client with that clientID
   *
   * @param client new Client Information
   * @return add success or not
   */
  boolean addClient(ClientDetails client);

  /** @return all clients */
  List<ClientDetails> listClient();

  void reset();
}
