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

package com.google.googleidentity.user;

import com.google.common.collect.ImmutableList;
import com.google.googleidentity.oauth2.exception.OAuth2ServerException;
import com.google.inject.Inject;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.sql.DataSource;

/** Jdbc Implementation for {@link UserDetailsService} */
public class JdbcUserDetailsService implements UserDetailsService {

  private final DataSource dataSource;

  private final Logger log = Logger.getLogger("JdbcUserDetailsService");

  @Inject
  JdbcUserDetailsService(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  @Override
  public Optional<UserDetails> getUserByName(String username) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM user " + "WHERE username = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, username);
      result = statement.executeQuery();
      if (result.next()) {
        Optional<UserDetails> user = Optional.ofNullable(buildUserFromJdbcResult(result));
        return user;
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
  public boolean updateUser(UserDetails user) {
    Connection conn = null;
    PreparedStatement statement = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt =
          "UPDATE user "
              + "SET password = ?, email = ?, google_account_id = ? "
              + "WHERE username = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, user.getPassword());
      statement.setString(2, user.getEmail());
      statement.setString(3, user.getGoogleAccountId());
      statement.setString(4, user.getUsername());
      int count = statement.executeUpdate();
      conn.commit();
      return count == 1;
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

  @Override
  public boolean addUser(UserDetails user) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "SELECT * FROM user WHERE username = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, user.getUsername());
      result = statement.executeQuery();
      if (!result.next()) {
        stmt = "INSERT INTO user VALUES (?, ?, ?, ?);";
        statement = conn.prepareStatement(stmt);
        statement.setString(1, user.getUsername());
        statement.setString(2, user.getPassword());
        statement.setString(3, user.getEmail());
        statement.setString(4, user.getGoogleAccountId());
        statement.execute();
        conn.commit();
        return true;
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
    return false;
  }

  @Override
  public Optional<UserDetails> getUserByEmailOrGoogleAccountId(String email, String gid) {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM user " + "WHERE email = ? OR google_account_id = ?;";
      statement = conn.prepareStatement(stmt);
      statement.setString(1, email);
      statement.setString(2, gid);
      result = statement.executeQuery();
      if (result.next()) {
        Optional<UserDetails> user = Optional.ofNullable(buildUserFromJdbcResult(result));
        return user;
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
  public List<UserDetails> listUser() {
    List<UserDetails> list = new LinkedList<>();
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      String stmt = "SELECT * FROM user;";
      statement = conn.prepareStatement(stmt);
      result = statement.executeQuery();
      while (result.next()) {
        list.add(buildUserFromJdbcResult(result));
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
    return ImmutableList.copyOf(list);
  }

  @Override
  public void reset() {
    Connection conn = null;
    PreparedStatement statement = null;
    ResultSet result = null;
    try {
      conn = dataSource.getConnection();
      conn.setAutoCommit(false);
      String stmt = "DELETE FROM user;";
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

  private UserDetails buildUserFromJdbcResult(ResultSet result) throws SQLException {
    return UserDetails.newBuilder()
        .setUsername(result.getString("username"))
        .setPassword(result.getString("password"))
        .setEmail(result.getString("email"))
        .setGoogleAccountId(result.getString("google_account_id"))
        .build();
  }
}
