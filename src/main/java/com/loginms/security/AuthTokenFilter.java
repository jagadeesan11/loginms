package com.loginms.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LogManager.getLogger(AuthTokenFilter.class);
    private static final Logger securityLogger = LogManager.getLogger("com.example.loginms.security");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        String clientIP = getClientIP(request);

        try {
            String jwt = parseJwt(request);

            if (jwt != null) {
                logger.debug("JWT token found in request to: {}", requestURI);

                if (jwtUtils.validateJwtToken(jwt)) {
                    String username = jwtUtils.getUserNameFromJwtToken(jwt);

                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(userDetails,
                                                                   null,
                                                                   userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    logger.debug("Successfully authenticated user: {} for request: {}", username, requestURI);
                    securityLogger.info("User {} authenticated via JWT for {} from IP: {}",
                                       username, requestURI, clientIP);
                } else {
                    logger.warn("Invalid JWT token provided for request: {} from IP: {}", requestURI, clientIP);
                    securityLogger.warn("Invalid JWT token attempt for {} from IP: {}", requestURI, clientIP);
                }
            } else {
                logger.debug("No JWT token found in request to: {}", requestURI);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication for request: {} from IP: {} - {}",
                        requestURI, clientIP, e.getMessage(), e);
            securityLogger.error("Authentication error for {} from IP: {} - {}",
                                requestURI, clientIP, e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return null;
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
