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

import org.apache.http.HttpStatus;

/**
 * OAuth2 Exceptions. Will be deal in try catch clause
 */
public class OAuth2Exception extends Exception{

    public enum ErrorCode{
        NO_RESPONSE_TYPE,
        UNSUPPORTED_RESPONSE_TYPE,
        NO_CLIENT_ID,
        NONEXISTENT_CLIENT_ID,
        UNAUTHORIZED_CLIENT,
        NO_REDIRECT_URI,
        REDIRECT_URI_MISMATCH,
        INVALID_SCOPE,
        ACCESS_DENIED,
        NO_GRANT_TYPE,
        UNSUPPORTED_GRANT_TYPE,
        NONEXISTENT_CODE,
        CODE_CLIENT_MISMATCH,
        CODE_REDIRECT_URI_MISMATCH,
        INVALID_CLIENT,
        NONEXISTENT_REFRESH_TOKEN,
        REFRESH_TOKEN_CLIENT_MISMATCH,
        NO_USER_CONSENT,
        NO_AUTHORIZATION_REQUEST
    }

    private ErrorCode errorCode;

    public int getHttpCode(){
        return HttpStatus.SC_BAD_REQUEST;
    }

    /**
     * Only use in Authorization Endpoint to judge redirect or not.
     */
    public boolean isRedirectable(){
        return true;
    }

    /**
     * Should be rewrite in specific exception classes.
     */
    public String getErrorType(){
        return "OAuth2Exception";
    }

    /**
     * Should be implemented in specific exception, default is empty.
     */
    public String getErrorDescription(){
        return "";
    }


    public OAuth2Exception(ErrorCode errorCode){
        super();
        this.errorCode = errorCode;
    }

    public ErrorCode getErrorCode() {
        return errorCode;
    }

}
