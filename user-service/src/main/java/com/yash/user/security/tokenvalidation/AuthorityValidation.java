package com.yash.user.security.tokenvalidation;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import org.springframework.beans.factory.annotation.Value;

import java.util.ArrayList;
import java.util.List;

import static io.jsonwebtoken.security.Keys.hmacShaKeyFor;

public class AuthorityValidation {

    @Value("${jwt.secret}")
    private String jwtSecret;

    public List<String> checkPermission(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret))).build()
                    .parseSignedClaims(token)
                    .getPayload();

            return claims.get("authorities", List.class);

        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

}