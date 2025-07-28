package com.loginms.service;

import com.loginms.dto.JwtResponse;
import com.loginms.dto.LoginRequest;
import com.loginms.dto.MessageResponse;
import com.loginms.dto.RegisterRequest;
import com.loginms.entity.User;
import com.loginms.repository.UserRepository;
import com.loginms.security.JwtUtils;
import com.loginms.security.UserPrincipal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger logger = LogManager.getLogger(AuthService.class);
    private static final Logger securityLogger = LogManager.getLogger("com.example.loginms.security");

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    public MessageResponse registerUser(RegisterRequest signUpRequest) {
        logger.info("Attempting to register new user with username: {} and email: {}",
                   signUpRequest.getUsername(), signUpRequest.getEmail());

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            logger.warn("Registration failed: Username {} already exists", signUpRequest.getUsername());
            return new MessageResponse("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            logger.warn("Registration failed: Email {} already exists", signUpRequest.getEmail());
            return new MessageResponse("Error: Email is already in use!");
        }

        try {
            // Create new user's account
            User user = new User(signUpRequest.getName(),
                               signUpRequest.getEmail(),
                               signUpRequest.getUsername(),
                               encoder.encode(signUpRequest.getPassword()),
                               signUpRequest.getRole());

            User savedUser = userRepository.save(user);

            logger.info("User registered successfully with ID: {}, username: {}, role: {}",
                       savedUser.getId(), savedUser.getUsername(), savedUser.getRole());
            securityLogger.info("New user registration: ID={}, username={}, email={}, role={}",
                               savedUser.getId(), savedUser.getUsername(), savedUser.getEmail(), savedUser.getRole());

            return new MessageResponse("User registered successfully!");

        } catch (Exception e) {
            logger.error("Error during user registration for username: {} - {}",
                        signUpRequest.getUsername(), e.getMessage(), e);
            throw new RuntimeException("Failed to register user: " + e.getMessage());
        }
    }

    public JwtResponse authenticateUser(LoginRequest loginRequest) {
        logger.info("Authentication attempt for user: {}", loginRequest.getUsernameOrEmail());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsernameOrEmail(),
                                                           loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);

            UserPrincipal userDetails = (UserPrincipal) authentication.getPrincipal();

            logger.info("User authenticated successfully: ID={}, username={}",
                       userDetails.getId(), userDetails.getUsername());
            securityLogger.info("Successful login: ID={}, username={}, email={}, role={}",
                               userDetails.getId(), userDetails.getUsername(),
                               userDetails.getEmail(), userDetails.getAuthorities().iterator().next().getAuthority());

            return new JwtResponse(jwt,
                                 userDetails.getId(),
                                 userDetails.getUsername(),
                                 userDetails.getEmail(),
                                 userDetails.getName(),
                                 userDetails.getAuthorities().iterator().next().getAuthority());

        } catch (Exception e) {
            logger.warn("Authentication failed for user: {} - {}",
                       loginRequest.getUsernameOrEmail(), e.getMessage());
            securityLogger.warn("Failed authentication attempt for user: {}",
                               loginRequest.getUsernameOrEmail());
            throw e; // Re-throw to be handled by GlobalExceptionHandler
        }
    }
}
