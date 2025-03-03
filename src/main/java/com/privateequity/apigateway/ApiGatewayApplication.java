package com.privateequity.apigateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {
    private static final Logger log = LoggerFactory.getLogger(ApiGatewayApplication.class);

    public static void main(String[] args) {
        System.out.println("🚀 API Gateway Started with Tracing Enabled!");
        log.info("🚀 Starting API Gateway...");
        SpringApplication.run(ApiGatewayApplication.class, args);
        log.info("✅ API Gateway Started Successfully!");
    }    }


