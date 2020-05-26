package com.galwebdemo.galwebauth.resource;


import com.galwebdemo.galwebauth.user.myUserDetails;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.http.HttpRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.ServletRequest;
import java.security.Principal;

@Controller
@RequestMapping("user")
public class UserController {

    @RequestMapping("me")
    public ModelAndView userpage(){

        myUserDetails user = (myUserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        ModelAndView view = new ModelAndView();

        view.setViewName("resource");

        view.addObject("username", user.getUsername());

        return view;
    }

    //Notify user whether the revoke request is success or not.
    @RequestMapping("revoke_success")
    public ModelAndView revokepage(ServletRequest request){

        myUserDetails user = (myUserDetails)SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        ModelAndView view = new ModelAndView();

        view.setViewName("revoke_page");

        view.addObject("success", request.getParameter("success"));

        return view;
    }
}
