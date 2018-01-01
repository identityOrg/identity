package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
public class AccessToken {
    @Id
    private String assessToken;

    private String userName;

    @Lob
    private String userProfile;

    private String clientId;

    private String scope;

    private LocalDateTime creationDate;

    private LocalDateTime expiryDate;
}
