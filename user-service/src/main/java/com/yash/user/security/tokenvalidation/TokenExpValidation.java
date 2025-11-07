package com.yash.user.security.tokenvalidation;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;


import static io.jsonwebtoken.security.Keys.hmacShaKeyFor;

@Component
public class TokenExpValidation {
    @Value("${jwt.secret}")
    private String SECRET_KEY;

    public boolean validateToken(String token) {
        if (SECRET_KEY == null || SECRET_KEY.isEmpty())
            throw new IllegalArgumentException("Not found secret key in structure");

        if (token.startsWith("Bearer "))
            token = token.replace("Bearer ", "");

        try {
            Claims claims = Jwts.parser()
                    .verifyWith(hmacShaKeyFor(Decoders.BASE64.decode(SECRET_KEY))).build()
                    .parseSignedClaims(token)
                    .getPayload();

            long currentTimeMillis = System.currentTimeMillis();
            return claims.getExpiration().getTime() >= currentTimeMillis;
        } catch (ExpiredJwtException ex) {
            throw new IllegalArgumentException("Token has expired.");
        } catch (MalformedJwtException ex) {
            throw new IllegalArgumentException("Invalid token.");
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Token validation error: " + ex.getMessage());
        }
    }
}
