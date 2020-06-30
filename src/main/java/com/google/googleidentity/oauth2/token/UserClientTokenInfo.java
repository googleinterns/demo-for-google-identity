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

package com.google.googleidentity.oauth2.token;

import com.google.common.io.BaseEncoding;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.InvalidParameterException;
import java.security.Key;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Used for encrypt username and clientID
 */
final class UserClientTokenInfo {
    private final String username;
    private final String clientID;
    private final String tokenValue;

    private static final Logger log = Logger.getLogger("UserClientTokenInfo");

    private final static String delimiter = "\t";

    UserClientTokenInfo(String username, String clientID, String tokenValue) {
        this.username = username;
        this.clientID = clientID;
        this.tokenValue = tokenValue;
    }

    public String getUsername() {
        return username;
    }

    public String getClientID() {
        return clientID;
    }

    /**
     * The random string generated for a token.
     */
    public String getTokenValue() {
        return tokenValue;
    }

    /**
     * The string contains information of username, client ID and tokenValue.
     * It is encrypt and send to user as token string.
     */
    public String getEncryptTokenString(Key aesKey) {
        String tokenInfo  = username + delimiter + clientID + delimiter + tokenValue;
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] bytesToEncrypt = tokenInfo.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedBytes = cipher.doFinal(bytesToEncrypt);
            return BaseEncoding.base64Url().encode(encryptedBytes);
        } catch (Exception e) {
            log.log(Level.INFO, "Error when encrypting tokenString!",  e);
            return null;
        }
    }

    public static UserClientTokenInfo decryptTokenString(Key aesKey, String tokenString) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            byte[] bytesToDecrypt = BaseEncoding.base64Url().decode(tokenString);
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] decryptedBytes = cipher.doFinal(bytesToDecrypt);
            String tokenInfoString = new String(decryptedBytes, StandardCharsets.UTF_8);
            String[] tokenInfo = tokenInfoString.split(delimiter);

            if (tokenInfo.length != 3) {
                throw new InvalidParameterException();
            }

            return new UserClientTokenInfo(tokenInfo[0], tokenInfo[1], tokenInfo[2]);
        } catch (Exception e) {
            log.log(Level.INFO, "Error when decrypting tokenString!",  e);
            throw new InvalidParameterException();
        }
    }

}
