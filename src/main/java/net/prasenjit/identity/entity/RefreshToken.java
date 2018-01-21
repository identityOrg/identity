package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_REFRESH_TOKEN")
public class RefreshToken {

    @Id
    @Column(name = "REFRESH_TOKEN", length = 50, nullable = false, unique = true)
    private String refreshToken;

    @Column(name = "USERNAME", length = 50, nullable = false)
    private String username;

    @Column(name = "CLIENT_ID", length = 50, nullable = false)
    private String clientId;

    @Column(name = "SCOPE", length = 50, nullable = false)
    private String scope;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE", nullable = false)
    private LocalDateTime expiryDate;

    @Column(name = "USED", nullable = false)
    private boolean used;

    public boolean isValid() {
        return LocalDateTime.now().isBefore(expiryDate) && !used;
    }
}
