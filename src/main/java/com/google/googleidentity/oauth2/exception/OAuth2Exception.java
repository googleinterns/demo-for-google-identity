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
public abstract class OAuth2Exception extends Exception {

    public OAuth2Exception() {
        super();
    }

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
     * Should be implemented in specific exception classes.
     */
    public abstract String getErrorType();

    /**
     * Should be implemented in specific exception, default is empty.
     */
    public abstract String getErrorDescription();

}
