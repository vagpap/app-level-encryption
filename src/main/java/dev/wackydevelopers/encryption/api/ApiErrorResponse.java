package dev.wackydevelopers.encryption.api;

import java.util.List;

public record ApiErrorResponse(ErrorBody error) {
    
    public record ErrorBody(String code, String message, List<Detail> details) {}

    public record Detail(String field, String issue) {}

    public static ApiErrorResponse of(String code, String message) {
        return new ApiErrorResponse(new ErrorBody(code, message, List.of()));
    }
}
