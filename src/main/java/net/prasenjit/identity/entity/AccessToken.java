package net.prasenjit.identity.entity;

import lombok.Data;
import net.prasenjit.identity.model.Profile;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "T_ACCESS_TOKEN")
public class AccessToken {
    @Id
    @Column(name = "ACCESS_TOKEN", length = 50)
    private String assessToken;

    @Column(name = "USERNAME", length = 50, nullable = false)
    private String username;

    @Lob
    @Column(name = "USER_PROFILE", nullable = false)
    @Convert(converter = ProfileConverter.class)
    private Profile userProfile;

    @Column(name = "CLIENT_ID", length = 50, nullable = false)
    private String clientId;

    @Column(name = "SCOPE", length = 500, nullable = false)
    private String scope;

    @Column(name = "CREATION_DATE", nullable = false)
    private LocalDateTime creationDate;

    @Column(name = "EXPIRY_DATE", nullable = false)
    private LocalDateTime expiryDate;

    public boolean isValid() {
        return LocalDateTime.now().isBefore(expiryDate);
    }
}
