package com.nttbank.microservices.cloudgateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Base64;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter
    implements WebFilter {

  private final ReactiveAuthenticationManager authenticationManager;
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
        .filter(authHeader -> authHeader.startsWith("Bearer "))
        .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
        .map(token -> token.replace("Bearer ", ""))
        .flatMap(token -> authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(null, token))
            .flatMap(authentication -> {
              String username = extractUsernameFromJwt(token); // Extract username
              log.info(username);
              ServerWebExchange modifiedExchange = exchange.mutate()
                  .request(builder -> builder.header("X-Username", username))
                  .build();
              return chain.filter(modifiedExchange)
                  .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
            })
        );
  }


  private String extractUsernameFromJwt(String jwtToken) {
    try {
      String[] parts = jwtToken.split("\\.");
      if (parts.length == 3) {
        String payload = new String(Base64.getDecoder().decode(parts[1]));
        Map<String, Object> payloadMap = objectMapper.readValue(payload, Map.class);
        return (String) payloadMap.get("username");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

}
