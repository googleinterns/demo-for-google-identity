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

package com.google.googleidentity.oauth2.exception;

import static com.google.googleidentity.oauth2.exception.OAuth2ExceptionHandler.ErrorCode;

/**
 * OAuth2 Exceptions. Will be deal in try catch clause
 * errorCode: error Code Defined in {@link OAuth2ExceptionHandler}
 */
public class OAuth2Exception extends Exception{

    private OAuth2ExceptionHandler.ErrorCode errorCode;

    public OAuth2Exception(ErrorCode errorCode){
        super();
        this.errorCode = errorCode;
    }

    public OAuth2ExceptionHandler.ErrorCode getErrorCode() {
        return errorCode;
    }
}
