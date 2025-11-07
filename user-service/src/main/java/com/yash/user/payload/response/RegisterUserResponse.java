package com.yash.user.payload.response;

import jakarta.validation.constraints.Size;
import lombok.*;


@Getter
@Setter
@Builder
@AllArgsConstructor
public class RegisterUserResponse {
    @Size(min = 10, max = 500)
    private String message;
}
