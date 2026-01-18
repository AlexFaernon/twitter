package com.ziminpro.ums.controllers;

import java.net.URI;
import java.util.Map;
import java.util.UUID;

import com.ziminpro.ums.auth.GitHubOAuthService;
import com.ziminpro.ums.auth.JwtService;
import com.ziminpro.ums.dao.UmsRepository;
import com.ziminpro.ums.dtos.Roles;
import com.ziminpro.ums.dtos.User;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private static final String STATE_COOKIE = "oauth_state";

    private final UmsRepository umsRepository;
    private final GitHubOAuthService gitHubOAuthService;
    private final JwtService jwtService;
    private final String frontendRedirect;

    public AuthController(
            UmsRepository umsRepository,
            GitHubOAuthService gitHubOAuthService,
            JwtService jwtService,
            @Value("${oauth.github.frontend-redirect:http://localhost:3000/}") String frontendRedirect
    ) {
        this.umsRepository = umsRepository;
        this.gitHubOAuthService = gitHubOAuthService;
        this.jwtService = jwtService;
        this.frontendRedirect = frontendRedirect;
    }

    // логин/пароль
    public record LoginRequest(String login, String password) {}
    public record LoginResponse(String token) {}

    @PostMapping("/login")
    public Mono<ResponseEntity<LoginResponse>> login(@RequestBody LoginRequest request) {
        if (request == null
                || request.login() == null || request.login().isBlank()
                || request.password() == null || request.password().isBlank()) {
            return Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).<LoginResponse>build());
        }

        String login = request.login().trim();

        return Mono.fromCallable(() -> {
                    User user = umsRepository.findUserByEmail(login);

                    if (user == null || user.getId() == null) {
                        user = umsRepository.findAllUsers().values().stream()
                                .filter(u -> u.getName() != null && u.getName().equalsIgnoreCase(login))
                                .findFirst()
                                .orElse(null);
                    }

                    if (user == null || user.getId() == null) {
                        return ResponseEntity
                                .status(HttpStatus.UNAUTHORIZED)
                                .<LoginResponse>build();
                    }

                    if (user.getPassword() == null || !user.getPassword().equals(request.password())) {
                        return ResponseEntity
                                .status(HttpStatus.UNAUTHORIZED)
                                .<LoginResponse>build();
                    }

                    String token = jwtService.issueToken(user.getId(), user.getEmail());
                    return ResponseEntity.ok(new LoginResponse(token));
                })
                .subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic());
    }

    // гитхаб
    @GetMapping("/github")
    public Mono<ResponseEntity<Void>> githubStart(ServerWebExchange exchange) {
        if (!gitHubOAuthService.isConfigured()) {
            return Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build());
        }

        String state = gitHubOAuthService.generateState();

        ResponseCookie cookie = ResponseCookie.from(STATE_COOKIE, state)
                .httpOnly(true)
                .secure(false)
                .path("/")
                .maxAge(300)
                .sameSite("Lax")
                .build();

        String authorizeUrl = gitHubOAuthService.buildAuthorizeUrl(state);

        return Mono.just(ResponseEntity.status(HttpStatus.FOUND)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .location(URI.create(authorizeUrl))
                .build());
    }

    @GetMapping("/github/callback")
    public Mono<ResponseEntity<Void>> githubCallback(
            ServerWebExchange exchange,
            @RequestParam("code") String code,
            @RequestParam(value = "state", required = false) String state
    ) {
        String cookieState = readCookie(exchange, STATE_COOKIE);
        if (cookieState == null || !cookieState.equals(state)) {
            return Mono.just(redirect(frontendRedirect + "?error=oauth_state"));
        }

        ResponseCookie clearStateCookie = ResponseCookie.from(STATE_COOKIE, "")
                .path("/")
                .maxAge(0)
                .build();

        return gitHubOAuthService.exchangeCodeForAccessToken(code)
                .flatMap(gitHubOAuthService::fetchUserProfile)
                .map(profile -> {
                    String email = profile.email();
                    if (email == null || email.isBlank()) {
                        return ResponseEntity.status(HttpStatus.FOUND)
                                .header(HttpHeaders.SET_COOKIE, clearStateCookie.toString())
                                .location(URI.create(frontendRedirect + "?error=no_email"))
                                .build();
                    }

                    User user = umsRepository.findUserByEmail(email);
                    if (user == null || user.getId() == null) {
                        user = createUserFromGithub(profile.name(), email);
                    }

                    String token = jwtService.issueToken(user.getId(), email);

                    return ResponseEntity.status(HttpStatus.FOUND)
                            .header(HttpHeaders.SET_COOKIE, clearStateCookie.toString())
                            .location(URI.create(frontendRedirect + "?token=" +
                                    java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8)))
                            .build();
                });
    }

    private User createUserFromGithub(String name, String email) {
        Map<String, Roles> roles = umsRepository.findAllRoles();

        Roles defaultRole = roles.getOrDefault("USER",
                roles.getOrDefault("ROLE_USER",
                        roles.values().stream().findFirst().orElse(new Roles(null, "USER", "Default"))
                ));

        User user = new User();
        user.setName((name == null || name.isBlank()) ? email : name);
        user.setEmail(email);
        // пароль не испольуется, но по схеме что-то надо закинуть
        user.setPassword(UUID.randomUUID().toString());
        user.addRole(new Roles(null, defaultRole.getRole(), null));

        UUID userId = umsRepository.createUser(user);
        user.setId(userId);
        return user;
    }

    private static String readCookie(ServerWebExchange exchange, String name) {
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(name);
        return cookie == null ? null : cookie.getValue();
    }

    private static ResponseEntity<Void> redirect(String url) {
        return ResponseEntity.status(302).location(URI.create(url)).build();
    }
}
