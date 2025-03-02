package org.firstspring.fifthapi.controller;

import lombok.Data;
import java.time.LocalDateTime;
import org.firstspring.fifthapi.model.Message;
import org.firstspring.fifthapi.model.UserEntity;
import org.firstspring.fifthapi.repository.MessageRepository;
import org.firstspring.fifthapi.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/messages")
public class MessageController {

    private final MessageRepository messageRepository;
    private final UserRepository userRepository;

    public MessageController(MessageRepository messageRepository, UserRepository userRepository) {
        this.messageRepository = messageRepository;
        this.userRepository = userRepository;
    }

    @PreAuthorize("hasRole('USER')")
    @PostMapping
    public ResponseEntity<String> addMessage(@RequestBody String content) {
        if (content == null || content.trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Message cannot be empty!");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getName() == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized access!");
        }

        Optional<UserEntity> userOptional = userRepository.findByUsername(authentication.getName());
        if (userOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found!");
        }

        Message message = new Message(content, userOptional.get());
        messageRepository.save(message);
        return ResponseEntity.ok("Message added successfully!");
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping
    public List<MessageDTO> getMessages() {
        return messageRepository.findAll().stream()
                .map(message -> new MessageDTO(
                        message.getId(),
                        message.getContent(),
                        message.getCreatedAt(),
                        message.getSender().getUsername()
                ))
                .collect(Collectors.toList());
    }

    @PreAuthorize("hasRole('USER')")
    @PutMapping("/{id}")
    public ResponseEntity<String> updateMessage(@PathVariable Long id, @RequestBody String newContent) {
        if (newContent == null || newContent.trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Message content cannot be empty!");
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ROLE_ADMIN"));

        Optional<Message> messageOptional = messageRepository.findById(id);
        if (messageOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Message not found!");
        }

        Message message = messageOptional.get();
        if (!message.getSender().getUsername().equals(username) && !isAdmin) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("You can only edit your own messages!");
        }

        message.setContent(newContent);
        messageRepository.save(message);
        return ResponseEntity.ok("Message updated successfully!");
    }
    @PreAuthorize("hasRole('USER')")
    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteMessage(@PathVariable Long id) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        boolean isAdmin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> role.equals("ROLE_ADMIN"));

        Optional<Message> messageOptional = messageRepository.findById(id);
        if (messageOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Message not found!");
        }

        Message message = messageOptional.get();
        if (!message.getSender().getUsername().equals(username) && !isAdmin) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("You can only delete your own messages!");
        }

        messageRepository.delete(message);
        return ResponseEntity.ok("Message deleted successfully!");
    }
}

@Data
class MessageDTO {
    private Long id;
    private String content;
    private LocalDateTime createdAt;
    private String senderName;

    public MessageDTO(Long id, String content, LocalDateTime createdAt, String senderName) {
        this.id = id;
        this.content = content;
        this.createdAt = createdAt;
        this.senderName = senderName;
    }
}