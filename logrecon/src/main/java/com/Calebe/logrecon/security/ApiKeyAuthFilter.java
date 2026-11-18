package com.Calebe.logrecon.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class ApiKeyAuthFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-API-Key";
    private static final int MIN_KEY_LENGTH = 32;

    private final byte[] expectedHash;

    public ApiKeyAuthFilter(String apiKey) {
        if (apiKey == null || apiKey.length() < MIN_KEY_LENGTH) {
            throw new IllegalStateException(
                    "LOGRECON_API_KEY must be set and have at least " + MIN_KEY_LENGTH + " characters");
        }
        this.expectedHash = sha256(apiKey);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String provided = request.getHeader(HEADER);
        if (provided != null && MessageDigest.isEqual(expectedHash, sha256(provided))) {
            var auth = new UsernamePasswordAuthenticationToken(
                    "sentinel", null, List.of(new SimpleGrantedAuthority("ROLE_SERVICE")));
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        // No key or wrong key: we do NOT reject here. We leave the request unauthenticated
        // and Spring Security's rules (below) answer 401. One place decides, not two.
        chain.doFilter(request, response);
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}