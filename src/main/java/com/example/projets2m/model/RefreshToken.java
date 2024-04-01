package com.example.projets2m.model;
import com.example.projets2m.Enum.Estatut;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.Date;


@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshToken {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String token;
    private String username;
    private Date dateExpiration;

    @Enumerated(EnumType.STRING)
    private Estatut statut;
    private LocalDateTime dateGeneration;
    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;



}
