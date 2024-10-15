package com.odin.authenticator.utility;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtTokenUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private long expirationTime; // in milliseconds

    @Value("${jwt.issuer}")
    private String issuer; // The JWT issuer

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes()); // Use a SecretKey derived from the secret string
    }

    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();
        return doGenerateToken(claims, username);
    }

    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject) // the user's identifier
                .setIssuedAt(new Date(System.currentTimeMillis())) // issue date
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime)) // expiration date
                .setIssuer(issuer) // set the issuer
                .signWith(getSigningKey(), SignatureAlgorithm.HS256) // Use SecretKey and HS256 for signing
                .compact();
    }

    public boolean validateToken(String token, String username) {
        final String tokenUsername = getUsernameFromToken(token);
        return (username.equals(tokenUsername) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return getExpirationDateFromToken(token).before(new Date());
    }

    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey()) // Use parserBuilder and SecretKey for parsing
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public Date getExpirationDateFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey()) // Use parserBuilder and SecretKey for parsing
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getExpiration();
    }
}
