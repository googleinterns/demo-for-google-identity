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

/**
 * OAuth2Exception with type "invalid_request"
 */
public class InvalidRequestException extends OAuth2Exception{

    private static final String INVALID_REQUEST = "invalid_request";

    public InvalidRequestException(ErrorCode errorCode) {
        super(errorCode);
    }

    @Override
    public String getErrorType(){
        return INVALID_REQUEST;
    }

    @Override
    public boolean isRedirectable(){
        switch(getErrorCode()){
            case NO_REDIRECT_URI:
                // fall through
            case REDIRECT_URI_MISMATCH:
                // fall through
            case NO_CLIENT_ID:
                // fall through
            case NONEXISTENT_CLIENT_ID:
                // fall through
            case NO_AUTHORIZATION_REQUEST:
                return false;
            case NO_USER_CONSENT:
                // fall through
            case NO_RESPONSE_TYPE:
                return true;
            default:
                throw new IllegalArgumentException();
        }

    }

    @Override
    public String getErrorDescription(){
        switch(getErrorCode()){
            case NO_RESPONSE_TYPE:
                return "No Response Type!";
            case NO_CLIENT_ID:
                return "No Client ID!";
            case NONEXISTENT_CLIENT_ID:
                return "Client ID does not exist!";
            case NO_REDIRECT_URI:
                return "No Redirect Uri!";
            case REDIRECT_URI_MISMATCH:
                return "Redirect Uri Mismatch!";
            default:
                throw new IllegalArgumentException(String.valueOf(getErrorCode()));
        }
    }


}
