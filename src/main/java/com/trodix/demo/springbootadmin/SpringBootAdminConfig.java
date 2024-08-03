package com.trodix.demo.springbootadmin;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import de.codecentric.boot.admin.server.config.EnableAdminServer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.UUID;

@Configuration
@EnableAdminServer
public class SpringBootAdminConfig {

    private final AdminServerProperties adminServer;

    public SpringBootAdminConfig(AdminServerProperties adminServer) {
        this.adminServer = adminServer;
    }

    @Bean
    public SecurityFilterChain springBootAdminServerFilterChain(HttpSecurity http) throws Exception {

        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl(this.adminServer.getContextPath() + "/");

        http
                .securityMatcher(this.adminServer.getContextPath() + "/**")
                .authorizeHttpRequests(req -> req.requestMatchers(this.adminServer.getContextPath() + "/assets/**")
                        .permitAll()
                        .requestMatchers(this.adminServer.getContextPath() + "/login")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                .formLogin(formLogin -> formLogin.loginPage(this.adminServer.getContextPath() + "/login")
                        .successHandler(successHandler))
                .logout((logout) -> logout.logoutUrl(this.adminServer.getContextPath() + "/logout"))
                .httpBasic(Customizer.withDefaults())
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .ignoringRequestMatchers(
                                new AntPathRequestMatcher(this.adminServer.getContextPath() + "/instances", HttpMethod.POST.toString()),
                                new AntPathRequestMatcher(this.adminServer.getContextPath() + "/instances/*", HttpMethod.DELETE.toString()),
                                new AntPathRequestMatcher(this.adminServer.getContextPath() + "/actuator/**")))
                .rememberMe(rememberMe -> rememberMe.key(UUID.randomUUID()
                                .toString())
                        .tokenValiditySeconds(1209600));

        return http.build();
    }

}
