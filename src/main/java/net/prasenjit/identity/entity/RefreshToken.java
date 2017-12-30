package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;
import java.time.LocalDateTime;

@Data
@Entity
public class RefreshToken {

    @Id
    private String refreshToken;

    private String userName;

    private String clientId;

    private String scope;

    private LocalDateTime creationDate;

    private LocalDateTime expiryDate;

    private int usageCount;
}
