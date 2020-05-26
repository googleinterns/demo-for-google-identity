package com.galwebdemo.galwebauth.config;

import com.galwebdemo.galwebauth.user.ExtendedUserDetailsService;
import com.galwebdemo.galwebauth.user.InMemoryUserDetailsService;
import com.google.inject.Guice;
import com.google.inject.Injector;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


import java.util.Arrays;

//configuration for security
@Configuration
@EnableWebSecurity
public class SecurityConfig  extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(getUserService()).passwordEncoder(passwordEncoder());
        //try to add user in memory for test
        ((ExtendedUserDetailsService)getUserService()).createUser(new User("user", passwordEncoder().encode("12345678"), Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))));
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic()
                .and().csrf().disable()
                .authorizeRequests()
                //these ports do not require user authentication
                .antMatchers("/login","/oauth2/token","/oauth2/check_token","/oauth2/redirect","/oauth2/revoke").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .logout().permitAll();
    }

    //allow access for static resource
    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/webjars/**", "/images/**", "/js/**", "/css/**","/html/**");
    }


    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public UserDetailsService getUserService(){
        return new InMemoryUserDetailsService();
    }

}
