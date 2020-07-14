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

/** OAuth2Exception with type "invalid_request" */
public final class InvalidRequestException extends OAuth2Exception {

  private static final String INVALID_REQUEST = "invalid_request";
  private final ErrorCode errorCode;

  public InvalidRequestException(ErrorCode errorCode) {
    super();
    this.errorCode = errorCode;
  }

  public String getErrorType() {
    return INVALID_REQUEST;
  }

  public String getErrorDescription() {
    switch (errorCode) {
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
      case NO_USER_CONSENT:
        return "No User consent information!";
      case NO_AUTHORIZATION_REQUEST:
        return "No request need to approve!";
      case INVALID_USER_CONSENT:
        return "Invalid user consent information!";
      case UNSUPPORTED_REQUEST_METHOD:
        return "Request method is not supported!";
      case NON_URL_ENCODED_URI:
        return "URI is in invalid format!";
      case IMPLICIT_GRANT_IN_TOKEN_ENDPOINT:
        return "Implicit flow is not supported at token endpoint!";
      case NO_AUTHORIZATION_CODE:
        return "No authorization code!";
      case NO_REFRESH_TOKEN:
        return "No refresh_token!";
      case NO_INTENT:
        return "No Intent!";
      case NO_ASSERTION:
        return "No assertion!";
      case UNSUPPORTED_INTENT:
        return "Unsupported intent!";
      case INVALID_JWT_ISS:
        return "Invalid jwt iss!";
      case INVALID_JWT:
        return "Invalid jwt!";
      case WRONG_JWT_AUD:
        return "Wrong jwt aud!";
      case NO_REVOKE_TOKEN:
        return "No token to revoke!";
      case INVALID_TOKEN_TYPE:
        return "Invalid token type!";
      default:
        throw new IllegalArgumentException(String.valueOf(errorCode));
    }
  }

  public enum ErrorCode {
    NO_REDIRECT_URI,
    REDIRECT_URI_MISMATCH,
    NO_CLIENT_ID,
    NONEXISTENT_CLIENT_ID,
    NO_AUTHORIZATION_REQUEST,
    NO_USER_CONSENT,
    INVALID_USER_CONSENT,
    NO_RESPONSE_TYPE,
    UNSUPPORTED_REQUEST_METHOD,
    NON_URL_ENCODED_URI,
    IMPLICIT_GRANT_IN_TOKEN_ENDPOINT,
    NO_AUTHORIZATION_CODE,
    NO_REFRESH_TOKEN,
    NO_INTENT,
    NO_ASSERTION,
    UNSUPPORTED_INTENT,
    INVALID_JWT_ISS,
    INVALID_JWT,
    WRONG_JWT_AUD,
    NO_REVOKE_TOKEN,
    INVALID_TOKEN_TYPE
  }
}
