package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.time.LocalDateTime;

@Data
@Entity
public class AccessToken {
    @Id
    private String assessToken;

    private String userName;

    private String userProfile;

    private String clientId;

    private String scope;

    private LocalDateTime creationDate;

    private LocalDateTime expiryDate;
}
