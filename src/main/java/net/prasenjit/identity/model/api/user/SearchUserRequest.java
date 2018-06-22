package net.prasenjit.identity.model.api.user;

import lombok.Data;
import net.prasenjit.identity.entity.Status;

@Data
public class SearchUserRequest {
    private String username;
    private Status status;
    private Boolean admin;
    private String firstName;
    private String lastName;
}
