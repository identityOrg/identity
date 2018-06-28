package net.prasenjit.identity.model.api.user;

import lombok.Data;
import net.prasenjit.identity.entity.Status;

@Data
public class SearchUserRequest {
    private String username;
    private Boolean locked;
    private Boolean active;
    private Boolean admin;
    private String firstName;
    private String lastName;
}
