package com.yash.user.payload.request;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@RequiredArgsConstructor
public class PasswordChangeRequest {
    String oldPassword;
    String newPassword;
    String confirmPassword;

}
