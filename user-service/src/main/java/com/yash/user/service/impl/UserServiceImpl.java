package com.yash.user.service.impl;

import com.nimbusds.jose.shaded.gson.Gson;
import com.yash.user.exception.EmailOrUsernameNotFoundException;
import com.yash.user.exception.PasswordNotFoundException;
import com.yash.user.exception.PhoneNumberNotFoundException;
import com.yash.user.exception.UserNotFoundException;
import com.yash.user.model.RoleName;
import com.yash.user.model.User;
import com.yash.user.payload.request.LoginRequest;
import com.yash.user.payload.request.PasswordChangeRequest;
import com.yash.user.payload.request.RegisterUserRequest;
import com.yash.user.payload.response.LoginResponse;
import com.yash.user.payload.response.UserResponse;
import com.yash.user.repository.UserRepository;
import com.yash.user.security.jwt.JwtProvider;
import com.yash.user.security.userprinciple.UserDetailService;
import com.yash.user.security.userprinciple.UserPrinciple;
import com.yash.user.service.RoleService;
import com.yash.user.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final UserDetailService userDetailsService;
    private final ModelMapper modelMapper;
    private final RoleService roleService;

    Gson gson = new Gson(); // google.code.gson
    // @Autowired
    //EventProducer eventProducer;

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Value("${refresh.token.url}")
    private String refreshTokenUrl;

    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           JwtProvider jwtProvider,
                           UserDetailService userDetailsService,
                           ModelMapper modelMapper,
                           RoleService roleService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.modelMapper = modelMapper;
        this.roleService = roleService;
    }


    @Override
    public Mono<User> register(RegisterUserRequest registerUserRequest) {
        return Mono.defer(() -> {
            if (existsByUsername(registerUserRequest.getUsername())) {
                return Mono.error(new EmailOrUsernameNotFoundException("The username " + registerUserRequest.getUsername() + " is existed, please try again."));
            }
            if (existsByEmail(registerUserRequest.getEmail())) {
                return Mono.error(new EmailOrUsernameNotFoundException("The email " + registerUserRequest.getEmail() + " is existed, please try again."));
            }
            if (existsByPhoneNumber(registerUserRequest.getPhone())) {
                return Mono.error(new PhoneNumberNotFoundException("The phone number " + registerUserRequest.getPhone() + " is existed, please try again."));
            }

            User user = modelMapper.map(registerUserRequest, User.class);
            user.setPassword(passwordEncoder.encode(registerUserRequest.getPassword()));
            user.setRoles(registerUserRequest.getRoles()
                    .stream()
                    .map(role -> roleService.findByName(mapToRoleName(role))
                            .orElseThrow(() -> new RuntimeException("Role not found in the database.")))
                    .collect(Collectors.toSet()));

            userRepository.save(user);
            return Mono.just(user);
        });
    }

    private RoleName mapToRoleName(String roleName) {
        return switch (roleName) {
            case "ADMIN", "admin", "Admin" -> RoleName.ADMIN;
            case "SUPER_ADMIN", "super_admin", "Super_Admin" -> RoleName.SUPER_ADMIN;
            case "USER", "user", "User" -> RoleName.USER;
            default -> null;
        };
    }


    @Override
    public Mono<LoginResponse> login(LoginRequest signInForm) {
        return Mono.fromCallable(() -> {
            String usernameOrEmail = signInForm.getUsername();
            boolean isEmail = usernameOrEmail.contains("@gmail.com");

            UserDetails userDetails;
            if (isEmail) {
                userDetails = userDetailsService.loadUserByEmail(usernameOrEmail);
            } else {
                userDetails = userDetailsService.loadUserByUsername(usernameOrEmail);
            }

            // check username
            if (userDetails == null) {
                throw new UserNotFoundException("User not found");
            }

            // Check password
            if (!passwordEncoder.matches(signInForm.getPassword(), userDetails.getPassword())) {
                throw new PasswordNotFoundException("Incorrect password");
            }

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    signInForm.getPassword(),
                    userDetails.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtProvider.createToken(authentication);
            String refreshToken = jwtProvider.createRefreshToken(authentication);

            UserPrinciple userPrinciple = (UserPrinciple) userDetails;

            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userResponse(UserResponse.builder()
                            .id(userPrinciple.id())
                            .fullname(userPrinciple.fullname())
                            .username(userPrinciple.username())
                            .email(userPrinciple.email())
                            .phone(userPrinciple.phone())
                            .gender(userPrinciple.gender())
                            .avatar(userPrinciple.avatar())
                            .roles(userPrinciple.roles())
                            .build())
                    .build();
        }).onErrorResume(Mono::error);
    }

    @Override
    public Mono<Void> logout() {
        return null;
    }

    @Override
    public Mono<UserResponse> update(Long userId, RegisterUserRequest update) {
        return null;
    }

    @Override
    public Mono<String> changePassword(PasswordChangeRequest request) {
        return null;
    }

    @Override
    public String delete(Long id) {
        return "";
    }

    @Override
    public Optional<UserResponse> findById(Long userId) {
        return Optional.empty();
    }

    @Override
    public Optional<UserResponse> findByUsername(String userName) {
        return Optional.empty();
    }

    @Override
    public Page<UserResponse> findAllUsers(int page, int size, String sortBy, String sortOrder) {
        return null;
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public boolean existsByPhoneNumber(String phone) {
        return userRepository.existsByPhoneNumber(phone);
    }
}
