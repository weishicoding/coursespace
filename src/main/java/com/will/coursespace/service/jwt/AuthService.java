package com.will.coursespace.service.jwt;

import com.will.coursespace.dto.*;
import com.will.coursespace.entity.RefreshToken;
import com.will.coursespace.entity.Role;
import com.will.coursespace.entity.User;
import com.will.coursespace.enums.RoleName;
import com.will.coursespace.exception.AppException;
import com.will.coursespace.repository.RoleRepository;
import com.will.coursespace.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;


@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtRefreshService jwtRefreshService;
    private final AuthenticationManager authenticationManager;
    private final RoleRepository roleRepository;

    @Transactional(rollbackFor = Exception.class)
    public ResponseEntity<?> registerUser(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            return new ResponseEntity<>(new ApiResponse(false, "Username is already taken"), HttpStatus.BAD_REQUEST);
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            return new ResponseEntity<>(new ApiResponse(false, "Email Address is already taken"), HttpStatus.BAD_REQUEST);
        }

        Role userRole = roleRepository.findByName(RoleName.USER).orElseThrow(
            () -> new AppException("User Role not set"));
        // Create new user
        User user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .roles(Collections.singleton(userRole))
                .build();

        userRepository.save(user);
        return ResponseEntity.ok("User register successfully");
    }

    public ResponseEntity<?> login(LoginRequest request, HttpServletResponse response) {
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found with username: " + request.getUsername())
                );
        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new AppException("Invalid credentials");
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtService.generateToken((CustomUserDetail)authentication.getPrincipal());
        // generate the refresh token
        RefreshToken refreshToken = jwtRefreshService.genarateRefreshToken(user);

        // add refresh token for http-only cookie
        Cookie refreshTokenCookie = new Cookie("refreshToken", String.valueOf(refreshToken.getId()));
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(true); // Use secure cookies in production
        refreshTokenCookie.setPath("/");

        response.addCookie(refreshTokenCookie);
        return ResponseEntity.ok(JwtAuthenticationResponse.builder()
                .accessToken(jwt)
                .roles(user.getRoles())
                .username(user.getUsername())
                .build());
    }

    @Transactional(rollbackFor = Exception.class)
    public ResponseEntity<?> logout(String refreshToken, HttpServletResponse response) {
        jwtRefreshService.deleteById(refreshToken);
        // Clear the refresh token cookie
        Cookie cookie = new Cookie("refreshToken", null);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return ResponseEntity.ok("Logout successfully");
    }
}