package com.server.casclient.config;

import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.util.Arrays;

@Configuration
public class CasClientConfiguration {

    /**
     * [현재 서비스에 대한 정보]
     * ExceptionTranslationFilter 의 doFilter 동작 중에 AccessDeniedException 이 발생하면
     * ExceptionTranslationFilter 에 있는 AuthenticationEntryPoint(CasAuthenticationEntryPoint)의 commence 가 실행 된다.
     * 이때 Cas 인증 서버로 이동해 로그인을 시도하게 되는데 Service 정보를 함께 전달 한다.
     * 인증 서버에서 인증 시도 후에 다시 서비스로 Redirect 할 때 service 의 URL 로 사용하기 위해서 이다.
     */
    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setService("http://localhost:9000/login/cas");
        serviceProperties.setSendRenew(false);
        return serviceProperties;
    }

    /**
     * Spring Security 에서 httpBasic 설정을 추가하게 되면 Default 로 BasicAuthenticationFilter 가 추가된다.
     * httpBasic().authenticationEntryPoint 를 이용해 AuthenticationEntryPoint 를 지정할 수 있는데,
     * CasAuthenticationEntryPoint 를 등록하기 위해 해당 Bean 을 추가한다.
     *
     * 인증이 필요한 페이지에 접근 시 AccessDeniedException 이 발생하면 CasAuthenticationEntryPoint 의 commence 가 실행된다.
     * Cas Server 의 로그인 페이지로 redirect 된다. (ServiceProperties Bean 참고)
     */
    @Bean
    @Primary
    public AuthenticationEntryPoint authenticationEntryPoint(ServiceProperties sP) {
        CasAuthenticationEntryPoint entryPoint
                = new CasAuthenticationEntryPoint();
        entryPoint.setLoginUrl("https://localhost:8443/cas/login");
        entryPoint.setServiceProperties(sP);
        return entryPoint;
    }


    /**
     * [티켓 유효성 체크]
     * 실행 되기 전 순서
     *  1. ExceptionTranslationFilter 진행 중에 AccessDeniedException 발생
     *  2. CasAuthenticationEntryPoint.commence 실행
     *  3. Cas 서버에서 인증 성공 후에 - CasAuthenticationFilter.doFilter 실행
     *  4. CasAuthenticationFilter.attemptAuthentication 실행
     *  5. AuthenticationManager.authenticate 실행
     *  6. ProviderManager.authenticate 실행
     *  7. AuthenticationProvider.authenticate 실행
     *  8. CasAuthenticationProvider.authenticate 실행
     *  9. 8번 실행 중에 authenticateNow 실행
     *  10. authenticateNow 메소드 안에서 ticketValidator 사용
     * 설명
     *  Cas 서버에서 인증 성공을 하게 되면 CasAuthenticationFilter 로 들어오게 된다.
     *  이 때 redirect 된 서비스가 인증요청을 보낸 서비스가 맞는지 확인하기 위해서 한번 더 체크를 한다.
     *  redirect 될 때 받은 ticket 과 현재 서비스의 이름을 다시 Cas 서버로 보내고
     *  일치 하면 XML 형식으로 응답을 받게 된다.
     *  이후에는 해당 xml 응답을 parsing 해서 UserDetails 로 변환한 뒤 CasAuthenticationToken 을 만들게 된다.
     */
    @Bean
    public TicketValidator ticketValidator() {
        return new Cas30ServiceTicketValidator(
                "https://localhost:8443/cas");
    }

    /**
     * CasAuthenticationFilter 가 동작할 때 실제로 인증을 처리하는 주체이다.
     * Filter 가 동작하는 중에 인증을 진행하게 된다.
     * Bean 으로 등록한 ServiceProperties, ticketValidator, UserDetailsService 가 이 때 사용되며
     * Key 는 CasAuthenticationToken 을 만들 때 인자로 쓰인다.
     */
    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider provider = new CasAuthenticationProvider();
        provider.setServiceProperties(serviceProperties());
        provider.setTicketValidator(ticketValidator());
        provider.setUserDetailsService(
                s -> new User("kennen", "Mellon", true, true, true, true,
                        AuthorityUtils.createAuthorityList("ROLE_ADMIN")));
        provider.setKey("CAS_PROVIDER_LOCALHOST_9000");
        return provider;
    }


    /**
     * 1. cas Server 에서 로그아웃이 완료되면 같은 ID로 로그인 되어 있는 모든 Client 서비스에 로그아웃 요청을 보낸다.
     * 요청 URL 은 Cas Server 에 등록되어 있는 ServiceId 를 사용한다.
     * Cas Server 에서 Client 의 로그아웃 요청을 보낼 때, logoutRequest 라는 parameter 를 함께 보내는데,
     * SingSignOutFilter 에서는 logoutRequest parameter 가 존재할 경우에 서비스 로그아웃 처리를 하게 된다.
     * 2. cas Server 에서 로그인이 완료되면(또는 이미 로그인 되어 있으면) 로그인 요청을 했던 Client 서비스에 redirect 한다.
     * 이때 ticket 이라는 parameter 를 함께 전달하는데, SingleSignOutHandler 에 ticket 을 저장한다.
     * 저장 방식은 현재 ID_TO_SESSION_KEY_MAPPING(Map)에 Key : SessionId, Value : ticket 으로 저장하고
     * MANAGED_SESSIONS(Map)에 key : ticket, Value : Session 으로 저장 한다.
     * 이렇게 저장하는 이유는 Cas Server 에서 각각의 Client 서비스에 로그아웃 요청을 보낼 때 사용하기 위해서다.
     * Cas Server 로 부터 로그아웃 요청을 받은 Client 는 함께 받은 xml 형식의 parameter 값에서 ticket 값을 얻는다.
     * ticket 값으로 MANAGED_SESSIONS 에서 Session 을 가져온 뒤 해당 session 을 만료 시킨다.
     * 이렇게 되면 Cas Server 를 통해 인증 완료한 뒤 저장되어 있던 session 이 만료 되기 때문에 인증이 만료된다.
     */
    @Bean
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setCasServerUrlPrefix("https://localhost:8443/cas");
        singleSignOutFilter.setIgnoreInitConfiguration(true);
        return singleSignOutFilter;
    }

    /**
     * cas Server 로그아웃을 하기 위한 filter 이다.
     * 기본 LogoutFilter 와는 별개로 존재 하고 FilterChain 순서 상 기본 LogoutFilter 앞에 위치한다.
     * /logout/cas URL 을 intercept 해서 Cas Server 로 redirection 한 뒤 전체 Logout 을 실행한다.
     * 서브는 관련된 모든 서비스에 로그아웃 요청을 전송하고 서비스에서는 SingleSignOutFilter 에서 HTTP 세션을 무효하 시키면서
     * 로그아웃이 된다.
     */
    @Bean
    public LogoutFilter casLogoutFilter() {
        LogoutFilter logoutFilter = new LogoutFilter( "https://localhost:8443/cas/logout",securityContextLogoutHandler());
        logoutFilter.setFilterProcessesUrl("/logout/cas");
        return logoutFilter;
    }


    /**
     * logout Filter 가 실행(doFilter) 될 때 해당 Handler 가 사용 된다.
     * 자세한 동작은 클래스 내부의 logout Method 를 확인 해보면 알겠지만
     * session 을 만료 시키고, SecurityContextHolder 의 SecurityContext 를 가져온 뒤
     * Authentication 객체를 null 로 만든다.
     */
    @Bean
    public SecurityContextLogoutHandler securityContextLogoutHandler() {
        return new SecurityContextLogoutHandler();
    }

    /**
     * [Cas 인증 필터]
     * ServiceProperties(Bean) 의 Service 에 등록된 url 로 요청이 오게 되면 실행 되는 Filter 이다.
     * 현재 프로젝트에서는 "https://localhost:9000/login/cas" 로 등록 해놨으며
     * 위 url 로 요청 시 실행된다.
     * Cas 서버에서 로그인 이후에 redirect 되는 URL 이라고 생각하면 된다.
     * (참고 : AuthenticationEntryPoint 이후 작업)
     */
    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setServiceProperties(serviceProperties()); // Bean 위치 : CasConfig.java
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

    /**
     * CasAuthenticationFilter 에서 사용되는 인증처리 관리자
     * 구현체는 ProviderManager 이며 Bean 으로 등록한 AuthenticationProvider 가 직접 인증절차를 진행한다.
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(Arrays.asList(casAuthenticationProvider()));
    }



}
