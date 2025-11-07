package com.yash.user.controllers;

import com.yash.user.payload.request.LoginRequest;
import com.yash.user.payload.request.RegisterUserRequest;
import com.yash.user.payload.response.LoginResponse;
import com.yash.user.payload.response.RegisterUserResponse;
import com.yash.user.payload.response.UserAutorizeResponse;
import com.yash.user.payload.response.UserResponse;
import com.yash.user.security.jwt.JwtProvider;
import com.yash.user.security.tokenvalidation.AuthorityValidation;
import com.yash.user.security.tokenvalidation.TokenExpValidation;
import com.yash.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;

@Slf4j
@Tag(name = "User Authentication API",
        description = "APIs for user registration, login, and authentication"
)
@RequiredArgsConstructor
@RestController
@RequestMapping("api/auth")
public class AuthController {
    @Autowired
    private final UserService userService;
    private final JwtProvider jwtProvider;
    // private final EmailService emailService;

    //User Registration API
    @Operation(summary = "Register a new user", description = "Registers a new user with the provided details.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "User created successfully", content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = RegisterUserResponse.class)))
            ,
            @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = RegisterUserResponse.class)))})
    @PostMapping({"/signup", "/register"})
    public Mono<RegisterUserResponse> register(@Valid @RequestBody RegisterUserRequest registerUserRequest) {
        return userService.register(registerUserRequest)
                .map(user -> new RegisterUserResponse("Create user: " + registerUserRequest.getUsername() + " successfully."))
                .onErrorResume(error -> Mono.just(new RegisterUserResponse("Error occurred while creating the account."))
                        .log());

    }

    //User Login || Sign-In API
    @Operation(summary = "User login", description = "Logs in a user with the provided credentials.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Login successful"),
            @ApiResponse(responseCode = "500", description = "Internal Server Error")
    })
    @PostMapping({"/signin", "/login"})
    public Mono<ResponseEntity<LoginResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
        return userService.login(loginRequest)
                .map(ResponseEntity::ok)
                .onErrorResume(error -> {
                    LoginResponse lgoinResponse = new LoginResponse(
                            null,
                            null,
                            new UserResponse()
                    );
                    return Mono.just(new ResponseEntity<>(lgoinResponse, HttpStatus.INTERNAL_SERVER_ERROR));
                });
    }

    //User Logout || Sign-Out API
    @Operation(summary = "User logout", description = "Logs out the authenticated user.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Logged out successfully"),
            @ApiResponse(responseCode = "400", description = "Bad Request")
    })
    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated() and hasAuthority('USER')")
    public Mono<ResponseEntity<String>> logout() {
        log.info("Logout endpoint called");
        return userService.logout()
                .then(Mono.just(new ResponseEntity<>("Logged out successfully.", HttpStatus.OK)))
                .onErrorResume(error -> {
                    log.error("Logout failed");
                    return Mono.just(new ResponseEntity<>("Logout failed.", HttpStatus.BAD_REQUEST));
                });
    }

    //Validate User Role || Authority access
    @Operation(summary = "Check user authority", description = "Checks if the user has the specified authority.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Role access API"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping({"/hasAuthority", "/authorization"})
    public Boolean getAuthority(@RequestHeader(name = "Authorization") String authorizationToken,
                                String requiredRole) {
        AuthorityValidation authorityTokenUtil = new AuthorityValidation();
        List<String> authorities = authorityTokenUtil.checkPermission(authorizationToken);

        if (authorities.contains(requiredRole)) {
            return ResponseEntity.ok(new UserAutorizeResponse("Role access api")).hasBody();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new UserAutorizeResponse("Invalid token")).hasBody();
        }
    }

    //Validate Token expiration or still alive
    @Operation(summary = "Validate JWT token", description = "Validates the provided JWT token.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token is valid"),
            @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping({"/validateToken", "/validate-token"})
    public Boolean validateToken(@RequestHeader(name = "Authorization") String authorizationToken) {
        TokenExpValidation validate = new TokenExpValidation();
        if (validate.validateToken(authorizationToken)) {
            return ResponseEntity.ok(new UserAutorizeResponse("Valid token")).hasBody();
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new UserAutorizeResponse("Invalid token")).hasBody();
        }
    }

}
