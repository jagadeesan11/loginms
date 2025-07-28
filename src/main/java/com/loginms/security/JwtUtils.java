package com.loginms.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private static final Logger logger = LogManager.getLogger(JwtUtils.class);
    private static final Logger securityLogger = LogManager.getLogger("com.example.loginms.security");

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private int jwtExpirationMs;

    public String generateJwtToken(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        try {
            String token = Jwts.builder()
                    .setSubject((userPrincipal.getUsername()))
                    .setIssuedAt(new Date())
                    .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                    .signWith(key(), SignatureAlgorithm.HS256)
                    .compact();

            logger.debug("JWT token generated successfully for user: {}", userPrincipal.getUsername());
            securityLogger.info("JWT token generated for user ID: {}, username: {}",
                               userPrincipal.getId(), userPrincipal.getUsername());

            return token;
        } catch (Exception e) {
            logger.error("Error generating JWT token for user: {} - {}",
                        userPrincipal.getUsername(), e.getMessage(), e);
            securityLogger.error("JWT token generation failed for user: {}",
                                userPrincipal.getUsername());
            throw new RuntimeException("Failed to generate JWT token", e);
        }
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        try {
            String username = Jwts.parserBuilder().setSigningKey(key()).build()
                       .parseClaimsJws(token).getBody().getSubject();

            logger.debug("Successfully extracted username from JWT token: {}", username);
            return username;
        } catch (Exception e) {
            logger.warn("Failed to extract username from JWT token: {}", e.getMessage());
            securityLogger.warn("JWT token username extraction failed: {}", e.getMessage());
            throw e;
        }
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            logger.debug("JWT token validation successful");
            return true;
        } catch (MalformedJwtException e) {
            logger.warn("Invalid JWT token: {}", e.getMessage());
            securityLogger.warn("Malformed JWT token received: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.warn("JWT token is expired: {}", e.getMessage());
            securityLogger.warn("Expired JWT token received: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.warn("JWT token is unsupported: {}", e.getMessage());
            securityLogger.warn("Unsupported JWT token received: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.warn("JWT claims string is empty: {}", e.getMessage());
            securityLogger.warn("Empty JWT claims received: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during JWT validation: {}", e.getMessage(), e);
            securityLogger.error("Unexpected JWT validation error: {}", e.getMessage());
        }

        return false;
    }
}
