package com.ziminpro.ums.auth;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@Service
public class GitHubOAuthService {

    private static final String GITHUB_OAUTH_AUTHORIZE = "https://github.com/login/oauth/authorize";
    private static final String GITHUB_OAUTH_TOKEN = "https://github.com/login/oauth/access_token";
    private static final String GITHUB_API_USER = "https://api.github.com/user";
    private static final String GITHUB_API_EMAILS = "https://api.github.com/user/emails";

    private final WebClient webClient;
    private final SecureRandom random = new SecureRandom();

    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final String scope;

    public GitHubOAuthService(
            WebClient.Builder webClientBuilder,
            @Value("${oauth.github.client-id:}") String clientId,
            @Value("${oauth.github.client-secret:}") String clientSecret,
            @Value("${oauth.github.redirect-uri:}") String redirectUri,
            @Value("${oauth.github.scope:read:user user:email}") String scope
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.scope = scope;

        this.webClient = webClientBuilder
                .defaultHeader(HttpHeaders.USER_AGENT, "twitter-clone-ums")
                .build();
    }

    public String generateState() {
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public boolean isConfigured() {
        return clientId != null && !clientId.isBlank()
                && clientSecret != null && !clientSecret.isBlank()
                && redirectUri != null && !redirectUri.isBlank();
    }

    public String buildAuthorizeUrl(String state) {
        return GITHUB_OAUTH_AUTHORIZE
                + "?client_id=" + urlEncode(clientId)
                + "&redirect_uri=" + urlEncode(redirectUri)
                + "&scope=" + urlEncode(scope)
                + "&state=" + urlEncode(state);
    }

    public Mono<String> exchangeCodeForAccessToken(String code) {
        return webClient.post()
                .uri(GITHUB_OAUTH_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .bodyValue(
                        java.util.Map.of(
                                "client_id", clientId,
                                "client_secret", clientSecret,
                                "code", code,
                                "redirect_uri", redirectUri
                        )
                )
                .retrieve()
                .onStatus(
                        status -> !status.is2xxSuccessful(),
                        response -> Mono.error(new RuntimeException("GitHub OAuth token request failed"))
                )
                .bodyToMono(GitHubTokenResponse.class)
                .map(GitHubTokenResponse::access_token)
                .filter(token -> token != null && !token.isBlank())
                .switchIfEmpty(Mono.error(new RuntimeException("No access token returned by GitHub")));
    }

    /**
     * Fetches GitHub user profile.
     * IMPORTANT: GitHub may not return email if it is hidden,
     * so we additionally fetch /user/emails.
     */
    public Mono<GitHubUserProfile> fetchUserProfile(String accessToken) {
        return webClient.get()
                .uri(GITHUB_API_USER)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus(
                        status -> !status.is2xxSuccessful(),
                        response -> Mono.error(new RuntimeException("GitHub user request failed"))
                )
                .bodyToMono(GitHubUserProfile.class)
                .flatMap(profile -> {
                    if (profile.email() != null && !profile.email().isBlank()) {
                        return Mono.just(profile);
                    }
                    return fetchPrimaryEmail(accessToken)
                            .map(email -> new GitHubUserProfile(
                                    profile.id(),
                                    profile.login(),
                                    profile.name(),
                                    email,
                                    profile.avatar_url()
                            ));
                });
    }

    private Mono<String> fetchPrimaryEmail(String accessToken) {
        return webClient.get()
                .uri(GITHUB_API_EMAILS)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .onStatus(
                        status -> !status.is2xxSuccessful(),
                        response -> Mono.error(new RuntimeException("GitHub emails request failed"))
                )
                .bodyToMono(GitHubEmail[].class)
                .map(emails -> {
                    Optional<GitHubEmail> primaryVerified = List.of(emails).stream()
                            .filter(e -> Boolean.TRUE.equals(e.primary()) && Boolean.TRUE.equals(e.verified()))
                            .findFirst();

                    if (primaryVerified.isPresent()) {
                        return primaryVerified.get().email();
                    }
                    return emails.length > 0 ? emails[0].email() : null;
                });
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** GitHub returns { access_token, scope, token_type } */
    public record GitHubTokenResponse(String access_token, String scope, String token_type) {
    }

    /** Subset of https://api.github.com/user */
    public record GitHubUserProfile(Long id, String login, String name, String email, String avatar_url) {
    }

    /** Subset of https://api.github.com/user/emails */
    public record GitHubEmail(String email, Boolean primary, Boolean verified, String visibility) {
    }
}
