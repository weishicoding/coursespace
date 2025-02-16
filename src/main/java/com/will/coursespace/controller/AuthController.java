package com.will.coursespace.controller;

import com.will.coursespace.dto.*;
import com.will.coursespace.entity.RefreshToken;
import com.will.coursespace.exception.AppException;
import com.will.coursespace.service.jwt.AuthService;
import com.will.coursespace.service.jwt.JwtRefreshService;
import com.will.coursespace.service.jwt.JwtService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Validated
@Slf4j
public class AuthController {

    private final AuthService authService;
    private final JwtService jwtService;
    private final JwtRefreshService jwtRefreshService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest request) {
        try {
            return authService.registerUser(request);
        } catch (Exception e) {
            log.info("User register failed");
            return ResponseEntity.ok("User register failed");
        }

    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        try {
            return authService.login(request, response);
        } catch (Exception e) {
            log.info("User login failed");
            return ResponseEntity.ok("User login failed");
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@CookieValue("refreshToken") String refreshToken) {
        try {
            return jwtRefreshService.findById(refreshToken)
                    .map(jwtRefreshService::verifyExpiration)
                    .map(RefreshToken::getUser)
                    .map(user -> {
                        var customUserDetail = CustomUserDetail.builder()
                                .username(user.getUsername())
                                .build();
                        String accessToken = jwtService.generateToken(customUserDetail);
                        return ResponseEntity.ok(JwtAuthenticationResponse.builder()
                                .accessToken(accessToken)
                                .roles(user.getRoles())
                                .username(user.getUsername())
                                .build());
                    }).orElseThrow(() -> new AppException("Refresh Token is not in DB.."));
        }catch (Exception e) {
            log.info("Refresh Token Failed", e);
            return new ResponseEntity<>("Refresh Token Failed", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> logoutUser(@CookieValue("refreshToken") String refreshToken, HttpServletResponse response) {
        try {
            return authService.logout(refreshToken, response);
        } catch (Exception e) {
            log.info("User logout failed");
            return ResponseEntity.ok("User logout failed");
        }

    }
}
