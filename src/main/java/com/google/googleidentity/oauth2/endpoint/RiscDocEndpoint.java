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

package com.google.googleidentity.oauth2.endpoint;

import com.google.inject.Singleton;
import java.io.IOException;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.minidev.json.JSONObject;

/**
 * Provide risc configuration including issuer and public key url
 */
@Singleton
public class RiscDocEndpoint extends HttpServlet {

  private static final long serialVersionUID = 13L;

  private static final Logger log = Logger.getLogger("RiscDocEndpoint");

  private JSONObject json;

  // Set it in appengine-web.xml
  private static String WEB_URL =
      System.getenv("WEB_URL") == null ? "localhost:8080" : System.getenv("WEB_URL");

  public void init() throws ServletException {
    json = new JSONObject();
    json.appendField("issuer", WEB_URL + "/oauth/risc");
    json.appendField("jwks_uri", WEB_URL + "/oauth2/risc/key");
  }

  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    response.getWriter().println(json.toJSONString());
    response.getWriter().flush();
  }
}
