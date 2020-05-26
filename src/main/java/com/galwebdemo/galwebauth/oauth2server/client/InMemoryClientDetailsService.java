/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.galwebdemo.galwebauth.oauth2server.client;



import com.galwebdemo.galwebauth.oauth2server.ClientDetails;
import com.galwebdemo.galwebauth.oauth2server.ClientDetailsService;
import com.galwebdemo.galwebauth.oauth2server.exception.GeneralException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class InMemoryClientDetailsService implements ClientDetailsService {

  private Map<String, ClientDetails> clientDetailsStore = new HashMap<String, ClientDetails>();

  private PasswordEncoder passwordEncoder;

  public ClientDetails getClientById(String clientId){
    ClientDetails details = clientDetailsStore.get(clientId);
    if (details == null) {
      throw new GeneralException("No client with requested id: " + clientId);
    }
    return details;
  }

  @Override
  public void addClient(ClientDetails clientDetails) {

    clientDetailsStore.put(clientDetails.getClientId(),clientDetails);

  }

  @Override
  public PasswordEncoder getPasswordEncoder(){
    return passwordEncoder;
  }

  public void setPasswordEncoder(PasswordEncoder passwordEncoder){
    this.passwordEncoder=passwordEncoder;
  }

  @Override
  public void updateClientDetails(ClientDetails clientDetails)  {
    clientDetailsStore.put(clientDetails.getClientId(), clientDetails);

  }

  @Override
  public void removeClientDetails(String clientId)  {
    clientDetailsStore.remove(clientId);
  }

  @Override
  public List<ClientDetails> listClientDetails() {
    return null;
  }

  public void setClientDetailsStore(Map<String, ? extends ClientDetails> clientDetailsStore) {
    this.clientDetailsStore = new HashMap<String, ClientDetails>(clientDetailsStore);
  }

}