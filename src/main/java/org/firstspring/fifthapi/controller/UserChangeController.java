package org.firstspring.fifthapi.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.firstspring.fifthapi.model.UserEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.firstspring.fifthapi.repository.UserRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api")
public class UserChangeController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserChangeController(UserRepository userRepository) {
        this.userRepository = userRepository;
        this.passwordEncoder = new BCryptPasswordEncoder();
    }

    @PutMapping("/change-user")
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
    @PutMapping("/toggle-account")
    @PreAuthorize("hasRole('ADMIN')") // Ensures only admins can access this endpoint
    public ResponseEntity<?> toggleUserAccount(@RequestBody ToggleAccountRequest request) {
        Optional<UserEntity> targetUserOpt = userRepository.findById(request.getUserId());
        if (targetUserOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }

        UserEntity targetUser = targetUserOpt.get();
        targetUser.setEnabled(request.isEnabled());
        userRepository.save(targetUser);

        return ResponseEntity.ok("User account " + (request.isEnabled() ? "enabled" : "disabled") + " successfully");
    }
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

@Setter
@Getter
class ToggleAccountRequest {
    private Long userId;
    private boolean enabled;
}