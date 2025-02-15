package com.will.coursespace.service.jwt;

import com.will.coursespace.dto.*;
import com.will.coursespace.dto.authentication.AuthenticationRequest;
import com.will.coursespace.dto.authentication.AuthenticationResponse;
import com.will.coursespace.entity.RefreshToken;
import com.will.coursespace.entity.User;
import com.will.coursespace.enums.RoleName;
import com.will.coursespace.exception.TokenRefreshException;
import com.will.coursespace.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;


@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuthenticationManager authenticationManager;

    @Transactional(rollbackFor = Exception.class)
    public AuthenticationResponse registerUser(RegisterRequest request) {
        // Create new user
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(RoleName.USER)
                .build();

        userRepository.save(user);
        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefresh(new HashMap<>(), user);
        log.info("User registered successfully: {}", request.getUsername());
        return AuthenticationResponse.builder()
                .token(token)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse login(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        User user = userRepository.findByEmail(request.getEmail()).orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));

        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefresh(new HashMap<>(), user);

        return AuthenticationResponse.builder()
                .token(token)
                .refreshToken(refreshToken)
                .build();
    }

    public ResponseEntity<?> logout(LogoutRequest request) {
        try {
            RefreshToken refreshToken = refreshTokenService.findByToken(request.getRefreshToken())
                    .orElseThrow(() -> new TokenRefreshException(request.getRefreshToken(),
                            "Refresh token is not in database!"));

            refreshTokenService.deleteByUserId(refreshToken.getUser().getId());
            SecurityContextHolder.clearContext();

            return ResponseEntity.ok("Log out successful!");
        } catch (Exception e) {
            log.error("Error during logout", e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error during logout");
        }
    }
}