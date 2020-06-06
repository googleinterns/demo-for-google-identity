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

import com.google.common.io.BaseEncoding;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.inject.Inject;
import com.google.inject.Singleton;

import java.util.Optional;
import java.util.Random;

import static com.google.common.io.BaseEncoding.base64Url;

/**
 * AuthorizationCodeService, generate Authorization Code and Store it
 */
@Singleton
public final class AuthorizationCodeService {

    private Random random = new Random();

    private CodeStore codeStore;

    private int codeLength = 10;

    private int byteLength = 7;

    @Inject
    public AuthorizationCodeService(CodeStore codeStore){
        this.codeStore = codeStore;
    }

    public void setCodeLength(int codeLength) {
        this.codeLength = codeLength;
        this.byteLength = ((codeLength-1)/4+1)*3-2;
    }

    /**
     * Generate a authorization code for the request, always success.
     * Because once a duplicate code generated, we will try another one.
     *
     * @param request
     * @return the generated code
     */
    public String getCodeForRequest(OAuth2Request request){

        String code = generateCode();

        while(!codeStore.setCode(code, request)){
            code = generateCode();
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

    private String generateCode(){

        byte[] bytes = new byte[byteLength];

        random.nextBytes(bytes);

        BaseEncoding hex = BaseEncoding.base64Url();

        return hex.encode(bytes).substring(0, codeLength);
    }

}
