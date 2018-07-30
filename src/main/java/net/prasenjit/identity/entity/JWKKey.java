package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_JWK_KEY")
public class JWKKey {
    @Id
    @Column(name = "ID", nullable = false)
    @GeneratedValue
    private Long id;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Lob
    @Column(name = "PRIVATE_KEY", nullable = false)
    private String privateKey;

    @Lob
    @Column(name = "PUBLIC_KEY", nullable = false)
    private String publicKey;
}
