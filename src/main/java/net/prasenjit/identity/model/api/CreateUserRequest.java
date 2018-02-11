package net.prasenjit.identity.model.api;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class CreateUserRequest {
    private String username;
    private boolean admin;
    private String firstName;
    private String lastName;
    private LocalDateTime expiryDate;
}
