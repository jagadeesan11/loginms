package com.example.loginms.exception;

import com.example.loginms.dto.MessageResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger = LogManager.getLogger(GlobalExceptionHandler.class);
    private static final Logger securityLogger = LogManager.getLogger("com.example.loginms.security");

    // Validation Exception Handler
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        Map<String, String> fieldErrors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            fieldErrors.put(fieldName, errorMessage);
        });

        Map<String, Object> errorResponse = createErrorResponse(
            "VALIDATION_ERROR",
            "Input validation failed",
            fieldErrors,
            request.getRequestURI()
        );

        logger.warn("Validation error at {}: {}", request.getRequestURI(), fieldErrors);
        return ResponseEntity.badRequest().body(errorResponse);
    }

    // Constraint Violation Exception Handler
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraintViolationException(
            ConstraintViolationException ex, HttpServletRequest request) {

        Map<String, String> violations = new HashMap<>();
        ex.getConstraintViolations().forEach(violation -> {
            violations.put(violation.getPropertyPath().toString(), violation.getMessage());
        });

        Map<String, Object> errorResponse = createErrorResponse(
            "CONSTRAINT_VIOLATION",
            "Constraint validation failed",
            violations,
            request.getRequestURI()
        );

        logger.warn("Constraint violation at {}: {}", request.getRequestURI(), violations);
        return ResponseEntity.badRequest().body(errorResponse);
    }

    // Authentication Exception Handlers
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentialsException(
            BadCredentialsException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "INVALID_CREDENTIALS",
            "Invalid username/email or password",
            null,
            request.getRequestURI()
        );

        securityLogger.warn("Failed login attempt from IP: {} at URI: {} - {}",
            getClientIP(request), request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleUsernameNotFoundException(
            UsernameNotFoundException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "USER_NOT_FOUND",
            "User not found",
            null,
            request.getRequestURI()
        );

        securityLogger.warn("User not found attempt from IP: {} at URI: {} - {}",
            getClientIP(request), request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticationException(
            AuthenticationException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "AUTHENTICATION_FAILED",
            "Authentication failed",
            null,
            request.getRequestURI()
        );

        securityLogger.warn("Authentication failed from IP: {} at URI: {} - {}",
            getClientIP(request), request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<Map<String, Object>> handleDisabledException(
            DisabledException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "ACCOUNT_DISABLED",
            "Account is disabled",
            null,
            request.getRequestURI()
        );

        securityLogger.warn("Disabled account access attempt from IP: {} at URI: {}",
            getClientIP(request), request.getRequestURI());

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<Map<String, Object>> handleLockedException(
            LockedException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "ACCOUNT_LOCKED",
            "Account is locked",
            null,
            request.getRequestURI()
        );

        securityLogger.warn("Locked account access attempt from IP: {} at URI: {}",
            getClientIP(request), request.getRequestURI());

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    // Authorization Exception Handler
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleAccessDeniedException(
            AccessDeniedException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "ACCESS_DENIED",
            "Access denied. You don't have permission to access this resource",
            null,
            request.getRequestURI()
        );

        securityLogger.warn("Access denied for IP: {} at URI: {} - {}",
            getClientIP(request), request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    // Database Exception Handlers
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrityViolationException(
            DataIntegrityViolationException ex, HttpServletRequest request) {

        String message = "Data integrity violation";
        if (ex.getMessage().contains("Duplicate entry")) {
            message = "Duplicate entry - resource already exists";
        }

        Map<String, Object> errorResponse = createErrorResponse(
            "DATA_INTEGRITY_VIOLATION",
            message,
            null,
            request.getRequestURI()
        );

        logger.error("Data integrity violation at {}: {}", request.getRequestURI(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    // HTTP Method Exception Handlers
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> handleHttpRequestMethodNotSupportedException(
            HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "METHOD_NOT_ALLOWED",
            "HTTP method not supported: " + ex.getMethod(),
            null,
            request.getRequestURI()
        );

        logger.warn("Unsupported HTTP method {} at {}", ex.getMethod(), request.getRequestURI());
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(errorResponse);
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoHandlerFoundException(
            NoHandlerFoundException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "ENDPOINT_NOT_FOUND",
            "The requested endpoint was not found",
            null,
            request.getRequestURI()
        );

        logger.warn("Endpoint not found: {} {}", ex.getHttpMethod(), ex.getRequestURL());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    // Request Parameter Exception Handlers
    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> handleMissingServletRequestParameterException(
            MissingServletRequestParameterException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "MISSING_PARAMETER",
            "Required parameter missing: " + ex.getParameterName(),
            null,
            request.getRequestURI()
        );

        logger.warn("Missing required parameter {} at {}", ex.getParameterName(), request.getRequestURI());
        return ResponseEntity.badRequest().body(errorResponse);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<Map<String, Object>> handleMethodArgumentTypeMismatchException(
            MethodArgumentTypeMismatchException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "INVALID_PARAMETER_TYPE",
            "Invalid parameter type for: " + ex.getName(),
            null,
            request.getRequestURI()
        );

        logger.warn("Invalid parameter type for {} at {}: expected {}",
            ex.getName(), request.getRequestURI(), ex.getRequiredType());
        return ResponseEntity.badRequest().body(errorResponse);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleHttpMessageNotReadableException(
            HttpMessageNotReadableException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "MALFORMED_REQUEST",
            "Malformed JSON request",
            null,
            request.getRequestURI()
        );

        logger.warn("Malformed JSON request at {}: {}", request.getRequestURI(), ex.getMessage());
        return ResponseEntity.badRequest().body(errorResponse);
    }

    // Runtime Exception Handler
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(
            RuntimeException ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "RUNTIME_ERROR",
            "An unexpected error occurred",
            null,
            request.getRequestURI()
        );

        logger.error("Runtime exception at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }

    // Generic Exception Handler
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(
            Exception ex, HttpServletRequest request) {

        Map<String, Object> errorResponse = createErrorResponse(
            "INTERNAL_SERVER_ERROR",
            "An unexpected error occurred",
            null,
            request.getRequestURI()
        );

        logger.error("Unexpected exception at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }

    // Helper Methods
    private Map<String, Object> createErrorResponse(String errorCode, String message, Object details, String path) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("timestamp", LocalDateTime.now());
        errorResponse.put("errorCode", errorCode);
        errorResponse.put("message", message);
        errorResponse.put("path", path);

        if (details != null) {
            errorResponse.put("details", details);
        }

        return errorResponse;
    }

    private String getClientIP(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }
}
