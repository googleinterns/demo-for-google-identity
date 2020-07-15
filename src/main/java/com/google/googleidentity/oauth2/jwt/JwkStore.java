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

package com.google.googleidentity.oauth2.jwt;

import com.google.inject.Singleton;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

/** Store key for signing */
@Singleton
public class JwkStore {
  private final int keyNum = 2;
  private final Random random = new Random();
  private Map<String, JWK> key = new HashMap<>();

  public JwkStore() throws JOSEException {
    for (int i = 0; i < keyNum; i++) {
      String keyID = UUID.randomUUID().toString();
      key.put(keyID, new RSAKeyGenerator(2048).keyID(keyID).keyUse(KeyUse.SIGNATURE).generate());
    }
  }

  public JWK getPublicJWK(String kid) {
    return key.get(kid).toPublicJWK();
  }

  public JWK getJWK() {
    return key.values().toArray(new JWK[0])[random.nextInt(keyNum)];
  }

  public String getJWKString() {
    JSONArray array = new JSONArray();
    for (JWK jwk : key.values()) {
      array.appendElement(jwk.toPublicJWK());
    }
    JSONObject json = new JSONObject();
    json.appendField("keys", array);
    return json.toJSONString();
  }
}
