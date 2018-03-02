package net.prasenjit.identity.model;

import lombok.Data;

import java.util.Date;

@Data
public class ApiError {
    private Date timestamp;
    private int status;
    private String error;
    private String message;
    private String path;
}
