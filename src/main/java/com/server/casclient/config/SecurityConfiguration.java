package com.server.casclient.config;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;
    @Autowired
    private SingleSignOutFilter singleSignOutFilter;
    @Autowired
    private LogoutFilter casLogoutFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().regexMatchers("/secured.*", "/login").authenticated()
                .and().authorizeRequests().antMatchers("/favicon.ico", "/static/**").permitAll()
                .and().authorizeRequests().antMatchers("/admin/**").hasAuthority("ADMIN")
                .and().authorizeRequests().antMatchers("/user/**").hasAuthority("USER")
                .and().authorizeRequests().regexMatchers("/").permitAll()
                .and().httpBasic().authenticationEntryPoint(authenticationEntryPoint)
                .and().csrf().disable()
                .logout().logoutSuccessUrl("/afterLogout")
                .and()
                .addFilterBefore(singleSignOutFilter, CasAuthenticationFilter.class)
                .addFilterBefore(casLogoutFilter, LogoutFilter.class);    }
}
