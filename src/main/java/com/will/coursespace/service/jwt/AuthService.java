package com.will.coursespace.service.jwt;

import com.will.coursespace.dto.*;
import com.will.coursespace.entity.RefreshToken;
import com.will.coursespace.entity.User;
import com.will.coursespace.enums.AuthProvider;
import com.will.coursespace.enums.Role;
import com.will.coursespace.exception.TokenRefreshException;
import com.will.coursespace.repository.RefreshTokenRepository;
import com.will.coursespace.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.stream.Collectors;


@Service
@Slf4j
@AllArgsConstructor
public class AuthService {
    private UserRepository userRepository;

    private RefreshTokenRepository refreshTokenRepository;

    private PasswordEncoder passwordEncoder;


    private JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    @Transactional
    public ResponseEntity<?> register(RegisterRequest request) {
        try {
            // Validate if username/email already exists
            if (userRepository.existsByUsername(request.getUsername())) {
                return ResponseEntity
                        .badRequest()
                        .body("Error: Username is already taken!");
            }

            if (userRepository.existsByEmail(request.getEmail())) {
                return ResponseEntity
                        .badRequest()
                        .body("Error: Email is already in use!");
            }

            // Create new user
            User user = new User();
            user.setUsername(request.getUsername());
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setProvider(AuthProvider.LOCAL);
            user.setRole(Role.USER);
            user.setEnabled(true);
            user.setCreatedAt(LocalDateTime.now());

            userRepository.save(user);

            log.info("User registered successfully: {}", request.getUsername());
            return ResponseEntity.ok("User registered successfully!");

        } catch (Exception e) {
            log.error("Error during registration", e);
            return ResponseEntity
                    .internalServerError()
                    .body("Error during registration");
        }
    }

    @Transactional
    public ResponseEntity<?> login(LoginRequest request) {
        try {
            var user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() ->
                            new UsernameNotFoundException("User not found with username: " + request.getUsername())
                    );
            if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                throw new AppException("Invalid credentials");
            }

            var authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String jwt = jwtService.generateToken((CustomUserDetail)authentication.getPrincipal());
            // generate the refresh token
            RefreshToken refreshToken = jwtService.generateToken(user.getUsername());

            // add refresh token for http-only cookie
            Cookie refreshTokenCookie = new Cookie("refreshToken", refreshToken.getId());
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true); // Use secure cookies in production
            refreshTokenCookie.setPath("/");

            response.addCookie(refreshTokenCookie);
            return ResponseEntity.ok(JwtAuthenticationResponse.builder()
                    .accessToken(jwt)
                    .roles(user.getRoles())
                    .username(user.getUsername())
                    .build());
        } catch (Exception e) {
            log.error("unauthorized", e);
            return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
        }
    }

    @Transactional
    public RefreshToken createRefreshToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Delete existing refresh token if any
        refreshTokenRepository.deleteByUser(user);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenExpiration));

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public ResponseEntity<?> refreshToken(RefreshTokenRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenRepository.findByToken(requestRefreshToken)
                .map(this::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    String newAccessToken = jwtService.generateToken(UserDetailsImpl.build(user));
                    return ResponseEntity.ok(new TokenRefreshResponse(newAccessToken, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException(request.getRefreshToken(), "Refresh token not found"));
    }

    private RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired");
        }
        return token;
    }

    @Transactional
    public ResponseEntity<?> logout(LogoutRequest request) {
        return refreshTokenRepository.findByToken(request.getRefreshToken())
                .map(token -> {
                    refreshTokenRepository.delete(token);
                    SecurityContextHolder.clearContext();
                    return ResponseEntity.ok("Logout successful");
                })
                .orElseThrow( () -> new TokenRefreshException(request.getRefreshToken(), "Refresh token not found"));
    }
}
