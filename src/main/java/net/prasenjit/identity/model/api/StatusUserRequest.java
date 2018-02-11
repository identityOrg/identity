package net.prasenjit.identity.model.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import net.prasenjit.identity.entity.Status;

@Data
public class StatusUserRequest {
    private Status status;
    private String password;
}
