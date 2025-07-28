package com.example.loginms.controller;

import com.example.loginms.dto.*;
import com.example.loginms.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LogManager.getLogger(AuthController.class);
    private static final Logger securityLogger = LogManager.getLogger("com.example.loginms.security");

    @Autowired
    AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                            HttpServletRequest request) {
        String clientIP = getClientIP(request);
        logger.info("Login attempt for user: {} from IP: {}", loginRequest.getUsernameOrEmail(), clientIP);

        try {
            JwtResponse jwtResponse = authService.authenticateUser(loginRequest);
            logger.info("Successful login for user: {} from IP: {}", loginRequest.getUsernameOrEmail(), clientIP);
            return ResponseEntity.ok(jwtResponse);
        } catch (Exception e) {
            logger.warn("Failed login attempt for user: {} from IP: {} - {}",
                    loginRequest.getUsernameOrEmail(), clientIP, e.getMessage());
            securityLogger.warn("Failed login attempt for user: {} from IP: {}",
                    loginRequest.getUsernameOrEmail(), clientIP);
            return ResponseEntity.badRequest()
                    .body(new MessageResponse("Error: Invalid username/email or password!"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest signUpRequest,
                                        HttpServletRequest request) {
        String clientIP = getClientIP(request);
        logger.info("Registration attempt for username: {}, email: {} from IP: {}",
                signUpRequest.getUsername(), signUpRequest.getEmail(), clientIP);

        MessageResponse response = authService.registerUser(signUpRequest);

        if (response.getMessage().startsWith("Error:")) {
            logger.warn("Registration failed for username: {} from IP: {} - {}",
                    signUpRequest.getUsername(), clientIP, response.getMessage());
            return ResponseEntity.badRequest().body(response);
        }

        logger.info("Successful registration for username: {} from IP: {}",
                signUpRequest.getUsername(), clientIP);
        return ResponseEntity.ok(response);
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
