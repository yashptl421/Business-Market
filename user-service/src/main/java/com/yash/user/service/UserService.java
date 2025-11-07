package com.yash.user.service;

import com.yash.user.model.User;
import com.yash.user.payload.request.LoginRequest;
import com.yash.user.payload.request.PasswordChangeRequest;
import com.yash.user.payload.request.RegisterUserRequest;
import com.yash.user.payload.response.LoginResponse;
import com.yash.user.payload.response.RegisterUserResponse;
import com.yash.user.payload.response.UserResponse;
import org.springframework.data.domain.Page;
import reactor.core.publisher.Mono;

import java.util.Optional;

public interface UserService {
    Mono<User> register(RegisterUserRequest registerUserRequest);

    Mono<LoginResponse> login(LoginRequest loginRequest);

    Mono<Void> logout();

    Mono<UserResponse> update(Long userId, RegisterUserRequest update);

    Mono<String> changePassword(PasswordChangeRequest request);

    //    Mono<String> resetPassword(ResetPasswordRequest resetPasswordRequest);
    String delete(Long id);

    Optional<UserResponse> findById(Long userId);

    Optional<UserResponse> findByUsername(String userName);

    Page<UserResponse> findAllUsers(int page, int size, String sortBy, String sortOrder);
}