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

package com.google.googleidentity.oauth2.token;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.googleidentity.oauth2.exception.OAuth2ServerException;
import com.google.googleidentity.oauth2.request.OAuth2Request;
import com.google.googleidentity.oauth2.util.OAuth2Utils;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import javax.inject.Inject;
import javax.sql.DataSource;

public class JdbcOAuth2TokenService implements OAuth2TokenService {

  private final DataSource dataSource;
  private final Logger log = Logger.getLogger("JdbcOAuth2TokenService");
  private boolean isRefreshTokenRotatable = false;
  private Duration tokenValidTime = Duration.ofMinutes(10);

  private ScheduledExecutorService service;

  @Inject
  public JdbcOAuth2TokenService(DataSource dataSource) {
    this.dataSource = dataSource;
    setTokenCleaner();
  }

  public void setRotateAndValidTime(boolean isRefreshTokenRotatable) {
    this.isRefreshTokenRotatable = isRefreshTokenRotatable;
  }

  private void setTokenCleaner() {
    service = Executors.newSingleThreadScheduledExecutor();
    service.scheduleAtFixedRate(new TokenCleaner(), 1, 1, TimeUnit.HOURS);
  }

  @Override
  public OAuth2AccessToken generateAccessToken(OAuth2Request request) {
    String clientID = request.getRequestAuth().getClientId();
    String username = request.getRequestAuth().getUsername();

    Optional<String> refreshTokenString = Optional.empty();

    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      if (request.getRequestBody().getRefreshable()) {
        String refreshTokenValue = UUID.randomUUID().toString();
        while (readRefreshToken(refreshTokenValue).isPresent()) {
          refreshTokenValue = UUID.randomUUID().toString();
        }
        refreshTokenString = Optional.of(refreshTokenValue);
        String stmt = "INSERT INTO refresh_token VALUES(?, ?, ?, ?, ?);";
        statement = conn.prepareStatement(stmt);
        statement.setString(1, refreshTokenValue);
        statement.setString(2, clientID);
        statement.setString(3, username);
        statement.setBoolean(4, request.getRequestBody().getIsScoped());
        statement.setString(5, String.join("\t", request.getRequestBody().getScopesList()));

        statement.execute();
        conn.commit();
      }
    } catch (SQLException exception) {
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        throw new OAuth2ServerException(exception1);
      }
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return getNewAccessToken(request, refreshTokenString);
  }

  @Override
  public Optional<OAuth2AccessToken> refreshToken(String refreshToken) {
    Optional<OAuth2RefreshToken> token = readRefreshToken(refreshToken);
    // The refreshToken may be wrong or not existed
    if (!token.isPresent()) {
      return Optional.empty();
    }

    String username = token.get().getUsername();
    String clientID = token.get().getClientId();

    OAuth2Request.Builder requestBuilder = OAuth2Request.newBuilder();
    requestBuilder.getRequestAuthBuilder().setClientId(clientID).setUsername(username);
    requestBuilder
        .getRequestBodyBuilder()
        .setIsScoped(token.get().getIsScoped())
        .addAllScopes(token.get().getScopesList())
        .setRefreshable(true);
    return Optional.of(getNewAccessToken(requestBuilder.build(), Optional.of(refreshToken)));
  }

  /**
   * Generate a new access token for a request. The refresh token is already there or no refresh
   * token is needed for the request.
   */
  private OAuth2AccessToken getNewAccessToken(
      OAuth2Request request, Optional<String> refreshTokenString) {

    String clientID = request.getRequestAuth().getClientId();
    String username = request.getRequestAuth().getUsername();

    String accessTokenValue = UUID.randomUUID().toString();

    while (readAccessToken(accessTokenValue).isPresent()) {
      accessTokenValue = UUID.randomUUID().toString();
    }

    OAuth2AccessToken.Builder builder =
        OAuth2AccessToken.newBuilder()
            .setAccessToken(accessTokenValue)
            .setClientId(request.getRequestAuth().getClientId())
            .setUsername(request.getRequestAuth().getUsername())
            .setIsScoped(request.getRequestBody().getIsScoped())
            .addAllScopes(request.getRequestBody().getScopesList())
            .setExpiredTime(
                Instant.now().plusSeconds(tokenValidTime.getSeconds()).getEpochSecond());
    refreshTokenString.ifPresent(builder::setRefreshToken);
    OAuth2AccessToken newToken = builder.build();

    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "INSERT INTO access_token VALUES(?, ?, ?, ?, ?, ?, ?);";
      statement = conn.prepareStatement(stmt);

      statement.setString(1, newToken.getAccessToken());
      statement.setString(2, newToken.getClientId());
      statement.setString(3, newToken.getUsername());
      statement.setBoolean(4, newToken.getIsScoped());
      statement.setString(5, String.join("\t", newToken.getScopesList()));
      statement.setLong(6, newToken.getExpiredTime());
      statement.setString(7, newToken.getRefreshToken());

      statement.execute();
      conn.commit();
    } catch (SQLException exception) {
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        throw new OAuth2ServerException(exception1);
      }
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return newToken;
  }

  @Override
  public Optional<OAuth2AccessToken> readAccessToken(String accessToken) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM access_token WHERE access_token = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, accessToken);
      result = statement.executeQuery();
      if (result.next()) {
        OAuth2AccessToken token = buildAccessTokenFromJdbcResult(result);
        return Optional.ofNullable(token);
      }
    } catch (SQLException exception) {
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return Optional.empty();
  }

  @Override
  public Optional<OAuth2RefreshToken> readRefreshToken(String refreshToken) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM refresh_token WHERE refresh_token = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, refreshToken);
      result = statement.executeQuery();
      if (result.next()) {
        OAuth2RefreshToken token = buildRefreshTokenFromJdbcResult(result);
        return Optional.ofNullable(token);
      }
    } catch (SQLException exception) {
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return Optional.empty();
  }

  @Override
  public boolean revokeByAccessToken(String accessToken) {
    Optional<OAuth2AccessToken> token = readAccessToken(accessToken);

    if (!token.isPresent()
        || Instant.ofEpochSecond(token.get().getExpiredTime()).isBefore(Instant.now())) {
      return false;
    }
    if (!Strings.isNullOrEmpty(token.get().getRefreshToken())) {
      return revokeByRefreshToken(token.get().getRefreshToken());
    }

    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "DELETE FROM access_token WHERE access_token = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, accessToken);
      statement.execute();
      conn.commit();
    } catch (SQLException exception) {
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        throw new OAuth2ServerException(exception1);
      }
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return true;
  }

  @Override
  public boolean revokeByRefreshToken(String refreshToken) {
    Optional<OAuth2RefreshToken> token = readRefreshToken(refreshToken);

    if (!token.isPresent()) {
      return false;
    }

    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "DELETE FROM refresh_token WHERE refresh_token = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, refreshToken);
      statement.execute();
      stmt = "DELETE FROM access_token WHERE refresh_token = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, refreshToken);
      statement.execute();
      conn.commit();
    } catch (SQLException exception) {
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        throw new OAuth2ServerException(exception1);
      }
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return true;
  }

  @Override
  public boolean revokeUserClientTokens(String username, String clientID) {
    if (listUserClientAccessTokens(username, clientID).isEmpty()) {
      return false;
    }
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "DELETE FROM refresh_token WHERE username = ? AND client_id = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, username);
      statement.setString(2, clientID);
      statement.execute();
      stmt = "DELETE FROM access_token WHERE username = ? AND client_id = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, username);
      statement.setString(2, clientID);
      statement.execute();
      conn.commit();
    } catch (SQLException exception) {
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        throw new OAuth2ServerException(exception1);
      }
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return true;
  }

  @Override
  public List<String> listUserClient(String username) {
    Set<String> clients = new HashSet<>();
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT DISTINCT client_id FROM access_token WHERE username = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, username);
      result = statement.executeQuery();
      while (result.next()) {
        clients.add(result.getString("client_id"));
      }
      stmt = "SELECT DISTINCT client_id FROM refresh_token WHERE username = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, username);
      result = statement.executeQuery();
      while (result.next()) {
        clients.add(result.getString("client_id"));
      }
    } catch (SQLException exception) {
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return ImmutableList.copyOf(clients);
  }

  @Override
  public List<OAuth2AccessToken> listUserClientAccessTokens(String username, String clientID) {
    List<OAuth2AccessToken> tokenList = new LinkedList<>();
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM access_token WHERE username = ? AND client_id = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, username);
      statement.setString(2, clientID);
      result = statement.executeQuery();
      while (result.next()) {
        tokenList.add(buildAccessTokenFromJdbcResult(result));
      }
    } catch (SQLException exception) {
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return ImmutableList.copyOf(tokenList);
  }

  @Override
  public List<OAuth2RefreshToken> listUserClientRefreshTokens(String username, String clientID) {
    List<OAuth2RefreshToken> tokenList = new LinkedList<>();
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM refresh_token WHERE username = ? AND client_id = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, username);
      statement.setString(2, clientID);
      result = statement.executeQuery();
      while (result.next()) {
        tokenList.add(buildRefreshTokenFromJdbcResult(result));
      }
    } catch (SQLException exception) {
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
    return ImmutableList.copyOf(tokenList);
  }

  @Override
  public void reset() {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "DELETE FROM refresh_token;";
      statement = conn.prepareStatement(stmt);
      statement.execute();
      stmt = "DELETE FROM access_token;";
      statement = conn.prepareStatement(stmt);
      statement.execute();
      conn.commit();
    } catch (SQLException exception) {
      try {
        if (conn != null) {
          conn.rollback();
        }
      } catch (SQLException exception1) {
        throw new OAuth2ServerException(exception1);
      }
      throw new OAuth2ServerException(exception);
    } finally {
      if (result != null) {
        try {
          result.close();
        } catch (SQLException exception2) {
          throw new OAuth2ServerException(exception2);
        }
      }
      if (statement != null) {
        try {
          statement.close();
        } catch (SQLException exception3) {
          throw new OAuth2ServerException(exception3);
        }
      }
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException exception4) {
          throw new OAuth2ServerException(exception4);
        }
      }
    }
  }

  private OAuth2AccessToken buildAccessTokenFromJdbcResult(ResultSet result) throws SQLException {
    return OAuth2AccessToken.newBuilder()
        .setAccessToken(result.getString("access_token"))
        .setClientId(result.getString("client_id"))
        .setUsername(result.getString("username"))
        .setIsScoped(result.getBoolean("is_scoped"))
        .addAllScopes(OAuth2Utils.parseScope(result.getString("scopes")))
        .setExpiredTime(result.getLong("expired_time"))
        .setRefreshToken(result.getString("refresh_token"))
        .build();
  }

  private OAuth2RefreshToken buildRefreshTokenFromJdbcResult(ResultSet result) throws SQLException {
    return OAuth2RefreshToken.newBuilder()
        .setRefreshToken(result.getString("refresh_token"))
        .setClientId(result.getString("client_id"))
        .setUsername(result.getString("username"))
        .setIsScoped(result.getBoolean("is_scoped"))
        .addAllScopes(OAuth2Utils.parseScope(result.getString("scopes")))
        .build();
  }

  private class TokenCleaner implements Runnable {

    @Override
    public void run() {
      Connection conn = null;
      PreparedStatement statement = null;
      ResultSet result = null;
      try {
        conn = dataSource.getConnection();
        conn.setAutoCommit(false);
        String stmt = "DELETE FROM refresh_token WHERE expired_time < ? ;";
        statement = conn.prepareStatement(stmt);
        statement.setLong(1, Instant.now().getEpochSecond());
        statement.execute();
        stmt = "DELETE FROM access_token WHERE expired_time < ? ;";
        statement = conn.prepareStatement(stmt);
        statement.setLong(1, Instant.now().getEpochSecond());
        statement.execute();
        conn.commit();

      } catch (SQLException exception) {
        try {
          if (conn != null) {
            conn.rollback();
          }
        } catch (SQLException exception1) {
          throw new OAuth2ServerException(exception1);
        }
        throw new OAuth2ServerException(exception);
      } finally {
        if (result != null) {
          try {
            result.close();
          } catch (SQLException exception2) {
            throw new OAuth2ServerException(exception2);
          }
        }
        if (statement != null) {
          try {
            statement.close();
          } catch (SQLException exception3) {
            throw new OAuth2ServerException(exception3);
          }
        }
        if (conn != null) {
          try {
            conn.close();
          } catch (SQLException exception4) {
            throw new OAuth2ServerException(exception4);
          }
        }
      }
    }
  }
}
