package com.yash.user.security.jwt;

import com.yash.user.security.userprinciple.UserPrinciple;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.security.core.GrantedAuthority;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static io.jsonwebtoken.security.Keys.hmacShaKeyFor;

@Component
public class JwtProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.expiration}")
    private int jwtExpiration;
    @Value("${jwt.refreshExpiration}")
    private int jwtRefreshExpiration;

    public String createToken(Authentication authentication) {
        UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();

        List<String> authorities = userPrinciple.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return Jwts.builder()
                .subject(userPrinciple.getUsername())
                .claim("authorities", authorities)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpiration * 1000L))
                .signWith(key())
                .compact();
    }

    private Key key() {
        return hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String createRefreshToken(Authentication authentication) {
        UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();
        return Jwts.builder()
                .subject(userPrinciple.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtRefreshExpiration * 1000L)) // jwtRefreshExpiration là thời gian hiệu lực của refresh token
                .signWith(key())
                .compact();
    }

   /* public String reduceTokenExpiration(String token) {
        // Decode the token to extract its claims
        Claims claims = Jwts.parser()
                .verifyWith(hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret))).build()
                .parseSignedClaims(token)
                .getPayload();

        // Reduce the expiration time by setting it to a past date
        claims.setExpiration(new Date(0));

        // Build a new token with the updated expiration time
        return Jwts.builder()
                .claims(claims)
                .signWith(key())
                .compact();
    }*/

    public Boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret))).build()
                    .parseSignedClaims(token);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid format Token -> Message: ", e);
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT Token -> Message: ", e);
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT Token -> Message: ", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty -> Message: ", e);
        }
        return false;
    }

    public String getUserNameFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret))).build()
                    .parseSignedClaims(token)
                    .getPayload();

            return claims.getSubject();
        } catch (Exception e) {
            return null;
        }
    }

}