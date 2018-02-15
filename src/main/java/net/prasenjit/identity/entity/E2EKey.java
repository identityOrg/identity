package net.prasenjit.identity.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.Serializable;
import java.time.Duration;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_E2E_KEY")
@IdClass(E2EKey.KeyId.class)
public class E2EKey {
    @Id
    @Column(name = "ASSOCIATION", nullable = false, length = 256)
    private String association;

    @Id
    @Column(name = "USER_TYPE", nullable = false, length = 10)
    @Enumerated(value = EnumType.STRING)
    private UserType userType;

    @Lob
    @Column(name = "CURRENT_PRIVATE_KEY", nullable = false)
    private String currentPrivateKey;

    @Lob
    @Column(name = "CURRENT_PUBLIC_KEY", nullable = false)
    private String currentPublicKey;

    @Lob
    @Column(name = "OLD_PRIVATE_KEY")
    private String oldPrivateKey;

    @Lob
    @Column(name = "OLD_PUBLIC_KEY")
    private String oldPublicKey;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    public boolean isValid(Duration validity) {
        return creationDate.plus(validity).isAfter(LocalDateTime.now());
    }

    public enum UserType {
        USER, CLIENT
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class KeyId implements Serializable {
        @Column(name = "ASSOCIATION", nullable = false, length = 256)
        private String association;

        @Column(name = "USER_TYPE", nullable = false, length = 10)
        @Enumerated(value = EnumType.STRING)
        private UserType userType;
    }
}
