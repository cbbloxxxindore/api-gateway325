package com.privateequity.apigateway.filter;

import com.privateequity.apigateway.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
public class JwtGlobalFilter implements GlobalFilter {
    private static final Logger log = LoggerFactory.getLogger(JwtGlobalFilter.class);

    private final JwtUtil jwtUtil;

    public JwtGlobalFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

                ServerHttpRequest request = exchange.getRequest();
        // 🔍 Log all incoming request headers
        log.info("Incoming request to: {}", request.getURI());
        request.getHeaders().forEach((key, value) -> log.info("Request Header: {} -> {}", key, value));

        // 🔍 Allow public routes
        if (request.getURI().getPath().contains("/auth/")) {
            return chain.filter(exchange);
        }

        // 🔍 Check Authorization header
        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            log.warn("❌ Missing Authorization Header");
            return onError(exchange, "Missing Authorization Header", HttpStatus.UNAUTHORIZED);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("❌ Invalid Authorization Header: {}", authHeader);

            return onError(exchange, "Invalid Authorization Header", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7);
        log.info("🔑 Extracted JWT: {}", token);

        // 🔍 Validate JWT
        if (!jwtUtil.validateToken(token)) {
            log.warn("❌ Invalid Token");
            return onError(exchange, "Invalid Token", HttpStatus.UNAUTHORIZED);
        }

        // 🔍 Extract roles and add to request headers
        List<String> roles = jwtUtil.extractRoles(token);
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                .header("X-User-Roles", String.join(",", roles)).build();
        // 🔍 Log the new headers added
        log.info("✅ Added X-User-Roles Header: {}", String.join(",", roles));

        log.info("✅ Response Status Code: {}", exchange.getResponse().getStatusCode());

       //last changes// return chain.filter(exchange.mutate().request(modifiedRequest).build());
        // 🔍 Log outgoing response status
        return chain.filter(exchange.mutate().request(modifiedRequest).build()).then(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            log.info("✅ Response Status Code: {}", response.getStatusCode());

            // Log all response headers
            for (Map.Entry<String, List<String>> entry : response.getHeaders().entrySet()) {
                log.info("Response Header: {} -> {}", entry.getKey(), entry.getValue());
            }
        }));

    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        log.error("❌ Error: {} | Status: {}", err, httpStatus);
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }
}
