package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_AUTHORIZATION_CODE")
public class AuthorizationCode {
    @Id
    @Column(name = "AUTHORIZATION_CODE", length = 50, nullable = false, unique = true)
    private String authorizationCode;

    @Column(name = "RETURN_URL", length = 500)
    private String returnUrl;

    @Column(name = "USERNAME", length = 50, nullable = false)
    private String username;

    @Column(name = "CLIENT_ID", length = 50, nullable = false)
    private String clientId;

    @Column(name = "SCOPE", length = 500, nullable = false)
    private String scope;

    @Column(name = "STATE", length = 50)
    private String state;

    @Column(name = "USED", nullable = false)
    private boolean used;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE", nullable = false)
    private LocalDateTime expiryDate;

    public boolean isValid() {
        return LocalDateTime.now().isBefore(expiryDate);
    }
}
