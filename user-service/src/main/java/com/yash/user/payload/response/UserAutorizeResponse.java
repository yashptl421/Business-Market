package com.yash.user.payload.response;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserAutorizeResponse {
    private String message;

    public UserAutorizeResponse() {

    }

    public UserAutorizeResponse(String messgae) {
        this.message = messgae;
    }
}
