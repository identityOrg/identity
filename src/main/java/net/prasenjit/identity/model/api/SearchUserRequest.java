package net.prasenjit.identity.model.api;

import lombok.Data;
import net.prasenjit.identity.entity.Status;

@Data
public class SearchUserRequest {
    private String username;
    private Status status;
    private boolean admin;
    private String firstName;
    private String lastName;
}
