package com.ziminpro.ums.auth;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    @Value("${security.jwt.secret}")
    private String secret;

    @Value("${security.jwt.issuer:ums}")
    private String issuer;

    @Value("${security.jwt.ttl-seconds:86400}")
    private long ttlSeconds;

    private Algorithm algorithm;

    @PostConstruct
    public void init() {
        this.algorithm = Algorithm.HMAC256(secret);
    }

    public String issueToken(UUID userId, String email) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(ttlSeconds);

        return JWT.create()
                .withIssuer(issuer)
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(exp))
                .withSubject(userId.toString())
                .withClaim("email", email)
                .sign(algorithm);
    }
}
