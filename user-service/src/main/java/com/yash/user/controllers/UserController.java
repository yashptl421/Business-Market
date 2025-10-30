package com.yash.user.controllers;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/user")
public class UserController {

    @Value("my.message")
    String value;

    @GetMapping
    public String getUser() {
        return value;
    }
}
