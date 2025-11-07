package com.yash.user.payload.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
public class LoginResponse {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("user_info")
    private UserResponse userResponse;
}
