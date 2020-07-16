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

import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.inject.Inject;
import com.google.protobuf.InvalidProtocolBufferException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.sql.DataSource;

/**
 * Jdbc implementation for {@link CodeStore}
 */
public class JdbcCodeStore implements CodeStore {

  private final DataSource dataSource;

  private final Logger log = Logger.getLogger("JdbcCodeStore");

  @Inject
  public JdbcCodeStore(DataSource dataSource){
    this.dataSource = dataSource;
  }

  @Override
  public Optional<OAuth2Request> consumeCode(String code) {
    try{
      Connection conn = dataSource.getConnection();
      String stmt = "SELECT * FROM code WHERE code = ?;";
      PreparedStatement statement = conn.prepareStatement(stmt);
      statement.setString(1, code);
      ResultSet result = statement.executeQuery();
      if(result.next()){
        stmt = "DELETE FROM code WHERE code = ?;";
        statement = conn.prepareStatement(stmt);
        statement.setString(1, code);
        statement.execute();
        Optional<OAuth2Request> client =
            Optional.ofNullable(
                OAuth2Request.parseFrom(
                    result.getBytes("request")));
        result.close();
        statement.close();
        conn.close();
        return client;
      }

    }catch(SQLException | InvalidProtocolBufferException exception){
      log.log(Level.INFO, "Get Client Error.", exception);
    }
    return Optional.empty();
  }

  @Override
  public boolean setCode(String code, OAuth2Request request) {
    try{
      Connection conn = dataSource.getConnection();
      String stmt = "SELECT * FROM code WHERE code = ?;";
      PreparedStatement statement = conn.prepareStatement(stmt);
      statement.setString(1, code);
      ResultSet result = statement.executeQuery();
      if(!result.next()){
        stmt = "INSERT INTO code VALUES(?, ?);";
        statement = conn.prepareStatement(stmt);
        statement.setString(1, code);
        statement.setBytes(2, request.toByteArray());
        statement.execute();
        result.close();
        statement.close();
        conn.close();
        return true;
      }

    }catch(SQLException exception){
      log.log(Level.INFO, "Get Client Error.", exception);
    }
    return false;
  }
}
