package com.yash.user.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum RoleName {
    USER,
    ADMIN,
    SUPER_ADMIN
}