package net.prasenjit.identity.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.time.LocalDateTime;

@Data
@Entity
public class AuthorizationCode {
    @Id
    @GeneratedValue
    private Long id;

    private String authorizationCode;

    private String returnUrl;

    private String userName;

    private String clientId;

    private String scope;

    private String state;

    private boolean used;

    private LocalDateTime creationDate;

    private LocalDateTime expiryDate;

    public boolean isValid() {
        return LocalDateTime.now().isBefore(expiryDate);
    }
}
