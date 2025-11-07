package com.yash.user.exception;

public class UserNotAuthenticatedException extends RuntimeException {
    public UserNotAuthenticatedException() {
        super();
    }

    public UserNotAuthenticatedException(String message) {
        super(message);
    }

    public UserNotAuthenticatedException(String message, Throwable cause) {
        super(message, cause);
    }
}