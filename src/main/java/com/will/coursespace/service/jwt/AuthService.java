package com.will.coursespace.service.jwt;

import com.will.coursespace.dto.LoginRequest;
import com.will.coursespace.dto.LogoutRequest;
import com.will.coursespace.dto.RefreshTokenRequest;
import com.will.coursespace.dto.RegisterRequest;
import com.will.coursespace.entity.RefreshToken;
import com.will.coursespace.entity.User;
import com.will.coursespace.enums.AuthProvider;
import com.will.coursespace.repository.RefreshTokenRepository;
import com.will.coursespace.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;


@Service
@Slf4j
public class AuthService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Value("${jwt.expiration}")
    private Long jwtExpiration;

    @Transactional
    public ResponseEntity<?> register(RegisterRequest request) {
        try {
            // Validate if username/email already exists
            if (userRepository.existsByUsername(request.getUsername())) {
                return ResponseEntity
                        .badRequest()
                        .body(new MessageResponse("Error: Username is already taken!"));
            }

            if (userRepository.existsByEmail(request.getEmail())) {
                return ResponseEntity
                        .badRequest()
                        .body(new MessageResponse("Error: Email is already in use!"));
            }

            // Create new user
            User user = new User();
            user.setUsername(request.getUsername());
            user.setEmail(request.getEmail());
            user.setPassword(passwordEncoder.encode(request.getPassword()));
            user.setProvider(AuthProvider.LOCAL);
            user.setRole(Role.ROLE_USER);
            user.setEnabled(true);
            user.setCreatedAt(LocalDateTime.now());

            userRepository.save(user);

            log.info("User registered successfully: {}", request.getUsername());
            return ResponseEntity.ok(new MessageResponse("User registered successfully!"));

        } catch (Exception e) {
            log.error("Error during registration", e);
            return ResponseEntity
                    .internalServerError()
                    .body(new MessageResponse("Error during registration"));
        }
    }

    @Transactional
    public ResponseEntity<?> login(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            String accessToken = jwtService.generateToken(userDetails);
            RefreshToken refreshToken = createRefreshToken(userDetails.getId());

            return ResponseEntity.ok(new AuthResponse(
                    accessToken,
                    refreshToken.getToken(),
                    "Bearer",
                    jwtExpiration,
                    userDetails.getUsername(),
                    userDetails.getAuthorities().stream()
                            .map(GrantedAuthority::getAuthority)
                            .collect(Collectors.toList())
            ));

        } catch (AuthenticationException e) {
            log.error("Authentication failed for user: {}", request.getUsername());
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("Invalid username or password"));
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
                .orElseThrow(() -> new TokenRefreshException("Refresh token not found"));
    }

    private RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException("Refresh token was expired");
        }
        return token;
    }

    @Transactional
    public ResponseEntity<?> logout(LogoutRequest request) {
        return refreshTokenRepository.findByToken(request.getRefreshToken())
                .map(token -> {
                    refreshTokenRepository.delete(token);
                    SecurityContextHolder.clearContext();
                    return ResponseEntity.ok(new MessageResponse("Logout successful"));
                })
                .orElseThrow(() -> new TokenRefreshException("Refresh token not found"));
    }
}
