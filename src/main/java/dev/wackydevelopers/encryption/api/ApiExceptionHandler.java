package dev.wackydevelopers.encryption.api;

import dev.wackydevelopers.encryption.blindindex.UnsupportedBlindIndexQueryException;
import dev.wackydevelopers.encryption.service.ResourceNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(ApiErrorResponse.of("VALIDATION_ERROR", ex.getMessage()));
    }

    @ExceptionHandler(UnsupportedBlindIndexQueryException.class)
    public ResponseEntity<ApiErrorResponse> handleUnsupportedQuery(UnsupportedBlindIndexQueryException ex) {
        return ResponseEntity.badRequest().body(ApiErrorResponse.of("UNSUPPORTED_QUERY", ex.getMessage()));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleNotFound(ResourceNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiErrorResponse.of("NOT_FOUND", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpected(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiErrorResponse.of("INTERNAL_SERVER_ERROR", "Unexpected error occurred"));
    }
}
