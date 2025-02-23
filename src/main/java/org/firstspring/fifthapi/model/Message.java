package org.firstspring.fifthapi.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "messages")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
public class Message {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String content;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false) // Foreign key to UserEntity
    private UserEntity sender;

    private LocalDateTime createdAt;

    public Message(String content, UserEntity sender) {
        this.content = content;
        this.sender = sender;
        this.createdAt = LocalDateTime.now(); // Automatically set the timestamp
    }
}
