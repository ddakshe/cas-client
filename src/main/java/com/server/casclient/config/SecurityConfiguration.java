package com.server.casclient.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationEntryPoint authenticationEntryPoint;
    @Autowired
    ServiceProperties serviceProperties;
    @Autowired
    private AuthenticationProvider authenticationProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().regexMatchers("/secured.*", "/login").authenticated()
                .and().authorizeRequests().antMatchers("/favicon.ico", "/static/**").permitAll()
                .and().authorizeRequests().antMatchers("/admin/**").hasAuthority("ADMIN")
                .and().authorizeRequests().antMatchers("/user/**").hasAuthority("USER")
                .and().authorizeRequests().regexMatchers("/").permitAll()
                .and().httpBasic().authenticationEntryPoint(authenticationEntryPoint);
    }

    /**
     * [Cas 인증 필터]
     * ServiceProperties(Bean) 의 Service 에 등록된 url 로 요청이 오게 되면 실행 되는 Filter 이다.
     * 현재 프로젝트에서는 "https://localhost:9xxx/login/cas" 로 등록 해놨으며
     * 위 url 로 요청 시 실행된다.
     * Cas 서버에서 로그인 이후에 redirect 되는 URL 이라고 생각하면 된다.
     * (참고 : AuthenticationEntryPoint 이후 작업)
     */
    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setServiceProperties(serviceProperties); // Bean 위치 : CasConfig.java
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

    /**
     * CasAuthenticationFilter 에서 사용되는 인증처리 관리자
     * 구현체는 ProviderManager 이며 Bean 으로 등록한 AuthenticationProvider 가 직접 인증절차를 진행한다.
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Arrays.asList(authenticationProvider));
    }
}
