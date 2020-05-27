package com.google.googleidentity.security;

import com.google.googleidentity.user.DefaultUserDetails;
import com.google.googleidentity.user.UserDetails;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Singleton
public class LoginCheckServlet extends HttpServlet {

    private static final long serialVersionUID = 4L;

    @Inject
    private Provider<UserSession> session = null;

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if(check(username, password)) {
            UserSession usersession = session.get();

            UserDetails user = new DefaultUserDetails(username, password, null);
            usersession.setUser(user);

            if(usersession.getOlduri().equals("")){
                response.sendRedirect("/resource/user");
            }
            else{
                response.sendRedirect(usersession.getOlduri());
            }

        }
        else{
            response.sendRedirect("/login");
        }

    }

    private boolean check(String username, String password){
        return true;
    }


}