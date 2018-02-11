package net.prasenjit.identity.model.api;

import lombok.Data;
import net.prasenjit.identity.entity.Status;

@Data
public class StatusClientRequest {
    private Status status;
}
