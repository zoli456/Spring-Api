package org.firstspring.fifthapi.controller;

import lombok.Getter;
import lombok.Setter;
import org.firstspring.fifthapi.model.RoleEntity;
import org.firstspring.fifthapi.model.UserEntity;
import org.firstspring.fifthapi.repository.RoleRepository;
import org.firstspring.fifthapi.repository.UserRepository;
import org.firstspring.fifthapi.security.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import java.util.Optional;

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public UserController(UserRepository userRepository, RoleRepository roleRepository, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody AuthRequest authRequest) {
        Optional<UserEntity> userOptional = userRepository.findByUsername(authRequest.getUsername());

        if (userOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }

        UserEntity user = userOptional.get();

        if (!passwordEncoder.matches(authRequest.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid username or password");
        }

        if (!user.isEnabled()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User is not enabled");
        }

        String token = jwtUtil.generateToken(user.getUsername());
        return ResponseEntity.ok(new AuthResponse(token));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid token");
        }

        String token = authHeader.substring(7); // Extract token without "Bearer "
        jwtUtil.blacklistToken(token);

        SecurityContextHolder.clearContext();
        return ResponseEntity.ok("User logged out successfully");
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        if (userRepository.findByUsername(registerRequest.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }

        if (userRepository.findByEmail(registerRequest.getEmail()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already in use");
        }

        UserEntity user = new UserEntity();
        user.setUsername(registerRequest.getUsername());
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setEnabled(true);

        RoleEntity role = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));
        user.getRoles().add(role);

        userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
    }

    @PutMapping("/change")
    public ResponseEntity<?> changeUserDetails(@Valid @RequestBody ChangeRequest changeRequest) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        Optional<UserEntity> currentUserOpt = userRepository.findByUsername(currentUsername);
        if (currentUserOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Current user not found");
        }
        UserEntity currentUser = currentUserOpt.get();

        boolean isAdmin = currentUser.getRoles().stream().anyMatch(role -> role.getName().equals("ROLE_ADMIN"));

        UserEntity targetUser;

        if (isAdmin && changeRequest.getUserId() != null) {
            // Admin updating another user
            Optional<UserEntity> targetUserOpt = userRepository.findById(changeRequest.getUserId());
            if (targetUserOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
            }
            targetUser = targetUserOpt.get();
        } else {
            // Regular user updating their own details
            targetUser = currentUser;
        }

        // Validate and set new username
        if (changeRequest.getNewUsername() != null && !changeRequest.getNewUsername().isEmpty()) {
            if (userRepository.findByUsername(changeRequest.getNewUsername()).isPresent() &&
                    !targetUser.getUsername().equals(changeRequest.getNewUsername())) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
            }
            targetUser.setUsername(changeRequest.getNewUsername());
        }

        // Validate and set new email
        if (changeRequest.getNewEmail() != null && !changeRequest.getNewEmail().isEmpty()) {
            if (userRepository.findByEmail(changeRequest.getNewEmail()).isPresent() &&
                    !targetUser.getEmail().equals(changeRequest.getNewEmail())) {
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Email already in use");
            }
            targetUser.setEmail(changeRequest.getNewEmail());
        }

        // Validate and set new password
        if (changeRequest.getNewPassword() != null && !changeRequest.getNewPassword().isEmpty()) {
            targetUser.setPassword(passwordEncoder.encode(changeRequest.getNewPassword()));
        }

        userRepository.save(targetUser);
        return ResponseEntity.ok("User details updated successfully");
    }


    @GetMapping("/userid")
    public ResponseEntity<?> getUserIdFromToken(@RequestHeader("Authorization") String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid token");
        }

        String username = jwtUtil.extractUsername(token.substring(7));
        Optional<UserEntity> userOpt = userRepository.findByUsername(username);

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }

        return ResponseEntity.ok(userOpt.get().getId());
    }
}
@Setter
@Getter
class AuthRequest {
    @NotBlank
    private String username;
    @NotBlank
    private String password;
}

@Getter
class AuthResponse {
    private String token;
    public AuthResponse(String token) {
        this.token = token;
    }
}

@Setter
@Getter
class RegisterRequest {
    @NotBlank
    @Size(min = 3, max = 20)
    private String username;

    @NotBlank
    @Size(min = 3, max = 50)
    private String password;

    @NotBlank
    @Email
    @Size(max = 50)
    private String email;
}

@Setter
@Getter
class ChangeRequest {
    private Long userId;

    @Size(min = 3, max = 20)
    private String newUsername;

    @Size(min = 3, max = 50)
    private String newPassword;

    @Email
    @Size(max = 50)
    private String newEmail;
}
