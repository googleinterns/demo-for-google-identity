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

public final class InvalidGrantException extends OAuth2Exception {
    public enum ErrorCode{
        NONEXISTENT_CODE,
        CODE_CLIENT_MISMATCH,
        NO_GRANT_TYPE,
        CODE_REDIRECT_URI_MISMATCH,
        NONEXISTENT_REFRESH_TOKEN,
        REFRESH_TOKEN_CLIENT_MISMATCH
    }

    private static final String INVALID_GRANT = "invalid_grant";

    private final ErrorCode errorCode;

    public InvalidGrantException(ErrorCode errorCode) {
        super();
        this.errorCode = errorCode;
    }

    @Override
    public String getErrorType() {
        return INVALID_GRANT;
    }

    @Override
    public String getErrorDescription() {
        switch(errorCode){
            case NONEXISTENT_CODE:
                return "Non existing code!";
            case CODE_CLIENT_MISMATCH:
                return "Code client mismatch!";
            case NO_GRANT_TYPE:
                return "No grant type!";
            case CODE_REDIRECT_URI_MISMATCH:
                return "Redirect uri mismatches the grant!";
            case NONEXISTENT_REFRESH_TOKEN:
                return "Refresh token does not exist!";
            case REFRESH_TOKEN_CLIENT_MISMATCH:
                return "Refresh token and client mismatch!";
            default:
                throw new IllegalArgumentException(String.valueOf(errorCode));
        }
    }
}
