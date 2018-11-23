package org.eso.example.security;

import java.util.HashSet;
import java.util.Set;

//import org.eso.example.CsrfHeaderFilter;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas30ServiceTicketValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
	/** CAS server base url https://www.eso.org/sso*/
    @Value("${cas.url.prefix}")
    String CAS_URL_PREFIX;

	/** On CAS server Where do we go when we need authentication. CAS server location https://www.eso.org/sso/login */
    @Value("${cas.service.login}")
    String CAS_URL_LOGIN;

    /** On CAS server Where do we go to logout. CAS server location https://www.eso.org/sso/logout */
    @Value("${cas.service.logout}")
    String CAS_URL_LOGOUT;
    
    /** CAS Endpoint to validate ST. eg: For CAS protocol v 3.0 this is https://www.eso.org/sso/p3/serviceValidate*/
    @Value("${cas.ticket.validate.url}")
    String CAS_VALIDATE_URL;
    
    /** This application url which needs to be secured by CAS like http://localhost:8086/login/cas.*/
    @Value("${app.service.security}")
    String CAS_SERVICE_URL;
    
    /** Home application url goes here where CAS will redirect  after logout. Must be configured on CAS side as allowed service*/
    @Value("${app.service.home}")
    String APP_SERVICE_HOME;
    
    /**Administrators of the application */
    @Value("${app.admin.userName:admin}")
    String APP_ADMIN_USER_NAME;

    /* 	
     * Sub url ('/login/cas') may not exists in application but is configured so that filter knows when to get activated.
	 * '/login/cas' is default filter parameter. It can be any other value but then have to be configured again in 
	 * CASAuthentication.setFilterProcessesUrl. Since default pattern ('/login/cas') value is being used so need to mention in  
	 * CASAuthentication.setFilterProcessesUrl
	 */
    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties sp = new ServiceProperties();
        sp.setService(CAS_SERVICE_URL);
        sp.setSendRenew(false);
        return sp;
    }

    @Bean
    public CasAuthenticationProvider casAuthenticationProvider() {
        CasAuthenticationProvider casAuthenticationProvider = new CasAuthenticationProvider();
        casAuthenticationProvider.setAuthenticationUserDetailsService(customUserDetailsService());
        casAuthenticationProvider.setServiceProperties(serviceProperties());
        casAuthenticationProvider.setTicketValidator(cas30ServiceTicketValidator());
        casAuthenticationProvider.setKey("an_id_for_this_auth_provider_only");
        return casAuthenticationProvider;
    }

    @Bean
    public AuthenticationUserDetailsService<CasAssertionAuthenticationToken> customUserDetailsService() {
        return new CustomUserDetailsService(adminList());
    }

    @Bean
    public SessionAuthenticationStrategy sessionStrategy() {
        SessionAuthenticationStrategy sessionStrategy = new SessionFixationProtectionStrategy();
        return sessionStrategy;
    }

    @Bean
    public Cas30ServiceTicketValidator cas30ServiceTicketValidator() {
        return new Cas30ServiceTicketValidator(CAS_VALIDATE_URL);
    }

    @Bean
    public CasAuthenticationFilter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter casAuthenticationFilter = new CasAuthenticationFilter();
        casAuthenticationFilter.setAuthenticationManager(authenticationManager());
        casAuthenticationFilter.setSessionAuthenticationStrategy(sessionStrategy());
        return casAuthenticationFilter;
    }
    
    public CasAuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint casAuthenticationEntryPoint = new CasAuthenticationEntryPoint();
        casAuthenticationEntryPoint.setLoginUrl(CAS_URL_LOGIN);
        casAuthenticationEntryPoint.setServiceProperties(serviceProperties());
        return casAuthenticationEntryPoint;
    }

    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter singleSignOutFilter = new SingleSignOutFilter();
        singleSignOutFilter.setCasServerUrlPrefix(CAS_URL_PREFIX);
        return singleSignOutFilter;
    }

    @Bean
    public LogoutFilter requestCasGlobalLogoutFilter() {
        LogoutFilter logoutFilter = new LogoutFilter(
                CAS_URL_LOGOUT + "?service=" + APP_SERVICE_HOME,
                new SecurityContextLogoutHandler());
        logoutFilter.setLogoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"));
        return logoutFilter;
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(casAuthenticationProvider());
    }
    
    /*List of application Admins */
    @Bean
    public Set<String> adminList() {
        Set<String> admins = new HashSet<String>();
        admins.add(APP_ADMIN_USER_NAME);
        return admins;
    }
    
    @Override
    public void configure(WebSecurity web) throws Exception {
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http 
        .exceptionHandling()
        		/*CAS filters goes here*/
        	    .authenticationEntryPoint(casAuthenticationEntryPoint()).and()
        	    .addFilter(casAuthenticationFilter())
                .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class)
                .addFilterBefore(requestCasGlobalLogoutFilter(), LogoutFilter.class)
                .authorizeRequests()
                /*mark secure paths*/
                .antMatchers("/login-check").authenticated()
                /*mark public paths*/
                .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                /**default Spring security created CSRF token needed by Angular*/
                .and().csrf()
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }
}
