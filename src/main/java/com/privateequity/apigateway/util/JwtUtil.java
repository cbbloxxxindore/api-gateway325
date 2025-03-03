package com.privateequity.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.function.Function;

import io.jsonwebtoken.SignatureAlgorithm;

import java.security.Key;
import java.util.List;

@Component
public class JwtUtil {

    private static final String SECRET_KEY = "IuRSpoaa9+hTKmYoUykAXzdmCaFj/Xnd73HE+SD1yTI="; // 🔑 Use a secure key

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> claims.get("roles", List.class));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public boolean validateToken(String token) {
        try {
            extractAllClaims(token); // 🔍 Check token validity
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(String username, List<String> roles) {
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles) // ✅ Store roles in token
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1 hour expiration
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}

//@Component
//public class JwtUtil {
//
//    //@Value("${jwt.secret}") // Read from application.yml
//    //private String SECRET;
//    // ✅ Generate signing key
//
//    private static SecretKey getSignKey() {
//        byte[] keyBytes = Decoders.BASE64.decode("IuRSpoaa9+hTKmYoUykAXzdmCaFj/Xnd73HE+SD1yTI=");
//        return Keys.hmacShaKeyFor(keyBytes);
//    }
//
//
//
//    // ✅ Extract all claims
//    public Claims extractAllClaims(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(getSignKey())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    // ✅ Extract username from token
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    // ✅ Extract roles from token
//    public String extractRoles(String token) {
//        return extractClaim(token, claims -> claims.get("roles", String.class));
//    }
//
//    // ✅ Generic method to extract a claim
//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }
//
//    // ✅ Validate token
//    public boolean validateToken(String token) {
//        try {
//            extractAllClaims(token);
//            return true;
//        } catch (Exception e) {
//            return false;
//        }
//    }
//
//    // Validate token and extract claims
//    public Claims extractAllClaims(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(getSignKey())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    // Check if token is expired
//    public Boolean isTokenExpired(String token) {
//        return extractClaim(token, Claims::getExpiration).before(new Date());
//    }
//
//    // Validate token (signature + expiration)
//    public Boolean validateToken(String token) {
//        try {
//            extractAllClaims(token);
//            return !isTokenExpired(token);
//        } catch (Exception e) {
//            return false;
//        }
//    }
//
//
//
//    // Generic claim extraction
//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }
//
//    // Extract username from token
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }}