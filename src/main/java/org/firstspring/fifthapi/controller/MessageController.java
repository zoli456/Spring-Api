package org.firstspring.fifthapi.controller;

import lombok.Data;
import java.time.LocalDateTime;
import org.firstspring.fifthapi.model.Message;
import org.firstspring.fifthapi.model.UserEntity;
import org.firstspring.fifthapi.repository.MessageRepository;
import org.firstspring.fifthapi.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
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