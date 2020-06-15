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

package com.google.googleidentity.oauth2.authorizationcode;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import java.util.Optional;
import java.util.Random;

/**
 * AuthorizationCodeService, generate Authorization Code and Store it
 */
@Singleton
public final class AuthorizationCodeService {

    private Random random = new Random();

    private final CodeStore codeStore;

    /**
     * The value is set in appengine-web.xml
     */
    private static final String AUTH_CODE_LENGTH = System.getenv("AUTH_CODE_LENGTH");

    private int codeLength = Integer.valueOf(AUTH_CODE_LENGTH);

    /**
     * Set the byteLength as the minimum one we need for
     * BaseEncoding.base64Url to generate a string with length of codeLength.
     * A char in base64Url need 6 bits (2^6 = 64) and a byte has 8 bits.
     * So byteLength = (codeLength * 6 - 1) / 8 + 1;
     */
    private int byteLength = (codeLength * 6 - 1) / 8 + 1;

    @Inject
    public AuthorizationCodeService(CodeStore codeStore){
        this.codeStore = codeStore;
    }

    /**
     * Set the byteLength as the minimum one we need for
     * BaseEncoding.base64Url to generate a string with length of codeLength.
     * A char in base64Url need 6 bits (2^6 = 64) and a byte has 8 bits.
     * So byteLength = (codeLength * 6 - 1) / 8 + 1;
     *
     */
    public void setCodeLength(int codeLength) {
        this.codeLength = codeLength;
        this.byteLength = (codeLength * 6 - 1) / 8 + 1;
    }

    /**
     * Generate a authorization code for the request, always success.
     * Because once a duplicate code generated, we will try another one.
     *
     * @return the generated code
     */
    public String getCodeForRequest(OAuth2Request request){

        String code =
                generateCode(
                        request.getRequestAuth().getClientId(),
                        request.getRequestAuth().getUsername());

        while(!codeStore.setCode(code, request)){
            code = generateCode(
                            request.getRequestAuth().getClientId(),
                            request.getRequestAuth().getUsername());
        }
        return code;
    }

    /**
     *
     * @param code
     * @return related request
     */
    public Optional<OAuth2Request> consumeCode(String code){
        return codeStore.consumeCode(code);
    }

  /**
   * Associate with client and username to reduce collisions.
   * When generating random bytes, set first numPrefixBytesToCopy bytes
   * as the first numPrefixBytesToCopy bytes of sha256(clientID + username).
   * To get enough randomness, numPrefixBytesToCopy = min(3, byteLength/2).
   */
  private String generateCode(String clientID, String username) {

      byte[] authCodeBytes = new byte[byteLength];

      random.nextBytes(authCodeBytes);

      int numPrefixBytesToCopy = Math.min(3, byteLength/2);
      byte[] prefixBytes =
              Hashing.sha256()
                      .hashString(clientID + username, Charsets.UTF_8).asBytes();

      System.arraycopy(prefixBytes, 0, authCodeBytes, 0 , numPrefixBytesToCopy);

      // Here we truncate the result since the encode hex may be longer the codeLength.
      return BaseEncoding.base64Url().encode(authCodeBytes).substring(0, codeLength);
    }

}
