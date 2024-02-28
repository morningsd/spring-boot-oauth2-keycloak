package com.demo.keycloak.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.DelegatingJwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        var delegatingJwtGrantedAuthoritiesConverter =
//                // Using the delegating converter multiple converters can be combined
                new DelegatingJwtGrantedAuthoritiesConverter(
//                        // First add the default converter
                        new JwtGrantedAuthoritiesConverter(),
//                        // Second add our custom Keycloak specific converter
                        new KeycloakJwtRolesConverter());

        http.authorizeRequests()
                .requestMatchers(new AntPathRequestMatcher("/public/**"), new AntPathRequestMatcher("/login/**"), new AntPathRequestMatcher("/oauth2/**"))
                .permitAll()
                .anyRequest()
                .authenticated();

        http.sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS);

        http.oauth2Login(Customizer.withDefaults());

        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(
                jwt -> new JwtAuthenticationToken(jwt, delegatingJwtGrantedAuthoritiesConverter.convert(jwt))
        );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        return http.getSharedObject(AuthenticationManagerBuilder.class).build();
    }
}
