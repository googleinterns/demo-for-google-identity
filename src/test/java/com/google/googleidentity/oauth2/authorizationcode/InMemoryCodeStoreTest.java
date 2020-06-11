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

import static com.google.common.truth.Truth.assertThat;
import com.google.googleidentity.oauth2.request.OAuth2Request;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test {@link InMemoryCodeStore}
 */
public class InMemoryCodeStoreTest {

    private static final String TEST_CODE = "123";

    private static final OAuth2Request oauth2Request =
            OAuth2Request.newBuilder()
                    .setRequestAuth(
                            OAuth2Request.RequestAuth.newBuilder()
                                    .setClientId(TEST_CODE))
                    .setRequestBody(
                            OAuth2Request.RequestBody.newBuilder()
                                    .setResponseType("code"))
                    .setAuthorizationResponse(
                            OAuth2Request.AuthorizationResponse.newBuilder()
                                    .setState(TEST_CODE))
                    .build();

    @Test
    void testInMemoryCodeStore_duplicateCode_canNotStore() {

        InMemoryCodeStore codeStore = new InMemoryCodeStore();

        assertTrue(codeStore.setCode(TEST_CODE, oauth2Request));

        assertFalse(codeStore.setCode(TEST_CODE, oauth2Request));
    }

    @Test
    void testInMemoryCodeStore_correctStore_correctConsume() {

        InMemoryCodeStore codeStore = new InMemoryCodeStore();

        assertTrue(codeStore.setCode(TEST_CODE, oauth2Request));

        assertThat(codeStore.consumeCode(TEST_CODE))
                .isEqualTo(Optional.ofNullable(oauth2Request));
    }

    @Test
    void testInMemoryCodeStore_noCode_consumeNull() {

        InMemoryCodeStore codeStore = new InMemoryCodeStore();

        assertThat(codeStore.consumeCode(TEST_CODE))
                .isEqualTo(Optional.empty());
    }

    @Test
    void testInMemoryCodeStore_CorrectConsume_codeDeleted() {

        InMemoryCodeStore codeStore = new InMemoryCodeStore();

        assertTrue(codeStore.setCode(TEST_CODE, oauth2Request));

        assertThat(codeStore.consumeCode(TEST_CODE))
                .isEqualTo(Optional.ofNullable(oauth2Request));

        assertThat(codeStore.consumeCode(TEST_CODE))
                .isEqualTo(Optional.empty());
    }

}
