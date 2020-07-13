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

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyConverter;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import java.io.IOException;
import java.security.Key;
import java.text.ParseException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Logger;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

/** Use kid to get the correct key */
public class JwtSigningKeyResolver extends SigningKeyResolverAdapter {

  private final Logger log = Logger.getLogger("JwtSigningKeyResolver");
  HashMap<String, Key> keyMap = new HashMap<>();

  public JwtSigningKeyResolver(String url) {
    CloseableHttpClient httpClient = HttpClients.createDefault();
    HttpGet httpget = new HttpGet(url);

    try {
      CloseableHttpResponse response = httpClient.execute(httpget);
      HttpEntity entity = response.getEntity();
      JSONObject json = JSONObjectUtils.parse(EntityUtils.toString(entity));

      JSONArray jsonArray = JSONObjectUtils.getJSONArray(json, "keys");

      List<JWK> jwkList = new LinkedList<JWK>();
      for (int i = 0; i < jsonArray.size(); i++) {
        jwkList.add(JWK.parse((JSONObject) jsonArray.get(i)));
      }
      List<Key> keyList = KeyConverter.toJavaKeys(jwkList);
      for (int i = 0; i < jsonArray.size(); i++) {
        JWK key = JWK.parse((JSONObject) jsonArray.get(i));
        keyMap.put(key.getKeyID(), keyList.get(i));
      }
    } catch (IOException | ParseException exception) {
      log.info("Jwt Key Error!");
    }
  }

  @Override
  public Key resolveSigningKey(JwsHeader jwsHeader, Claims claims) {
    // inspect the header or claims, lookup and return the signing key

    String keyId = jwsHeader.getKeyId(); // or any other field that you need to inspect
    return keyMap.get(keyId);
  }
}
