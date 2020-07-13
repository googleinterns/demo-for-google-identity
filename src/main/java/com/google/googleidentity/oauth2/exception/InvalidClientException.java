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

public final class InvalidClientException extends OAuth2Exception {

  private static final String INVALID_CLIENT = "invalid_client";

  public InvalidClientException() {
    super();
  }

  @Override
  public int getHttpCode() {
    return HttpStatus.SC_UNAUTHORIZED;
  }

  public String getErrorType() {
    return INVALID_CLIENT;
  }

  public String getErrorDescription() {
    return "Client Authentication Failed!";
  }
}
