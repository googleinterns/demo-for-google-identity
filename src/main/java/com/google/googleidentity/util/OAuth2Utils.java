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

package com.google.googleidentity.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/**
 * OAuth2 Util class
 */

public final class OAuth2Utils {

    private static final Logger log = Logger.getLogger("OAuth2Utils");

    public static String toHex(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length ; i++){
            int value = bytes[i] & 0xFF;
            if(value < 16){
                sb.append("0");
            }
            sb.append(Integer.toHexString(value));
        }
        return sb.toString();
    }

    public static String MD5(String password){
        MessageDigest md5 = null;

        try {
            md5 = MessageDigest.getInstance("MD5");
        }
        catch(NoSuchAlgorithmException e){
            log.info("No MD5 Algorithm");
            e.printStackTrace();
        }

        md5.update(password.getBytes());

        return toHex(md5.digest());
    }
}
