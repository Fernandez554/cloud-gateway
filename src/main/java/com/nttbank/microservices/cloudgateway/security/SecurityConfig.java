package com.nttbank.microservices.cloudgateway.security;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private final JwtAuthenticationFilter authenticationFilter;

  @Bean
  public SecurityWebFilterChain configure(ServerHttpSecurity http) {
    return http.authorizeExchange(auth -> auth
            .pathMatchers("/auth/**").permitAll()
            .pathMatchers("/api/customer-service/**").permitAll()
            .pathMatchers("/api/wallet-service/**").hasAnyRole("USER", "ADMIN")
            .pathMatchers("/api/account-service/**").permitAll()
            .pathMatchers("/api/debitcard-service/**").permitAll()
            .anyExchange().authenticated()
        )
        .addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .build();
  }

}
