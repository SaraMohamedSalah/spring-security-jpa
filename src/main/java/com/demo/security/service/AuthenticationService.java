package com.demo.security.service;

import com.demo.security.config.CustomUserDetailsService;
import com.demo.security.config.JwtUtils;
import com.demo.security.models.AuthenticationRequest;
import com.demo.security.models.AuthenticationResponse;
import com.demo.security.repository.Token;
import com.demo.security.repository.TokenRepository;
import com.demo.security.repository.User;
import com.demo.security.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var jwtToken = jwtUtils.generateTokenFromUsername(request.getEmail());
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .build();
    }

    public Optional<AuthenticationResponse> refreshToken(HttpServletRequest request) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            return Optional.empty();
        }
        refreshToken = authHeader.substring(7);
        userEmail = jwtUtils.getUserNameFromJwtToken(refreshToken);
        if (userEmail != null) {
            UserDetails user = customUserDetailsService.loadUserByUsername(userEmail);
            if (jwtUtils.validateJwtToken(refreshToken, user.getUsername())) {
                String accessToken = jwtUtils.generateTokenFromUsername(user.getUsername());
                return Optional.of(AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build());
            }
        }
        return Optional.empty();
    }

    public AuthenticationResponse register(AuthenticationRequest request) {
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        User savedUser = userRepository.save(user);
        String jwtToken = jwtUtils.generateTokenFromUsername(user.getUsername());
        String refreshToken = jwtUtils.generateTokenFromUsername(user.getUsername());
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }
}
