package net.prasenjit.identity.model;

import java.util.Date;

import lombok.Data;

@Data
public class ApiError {
	private Date timestamp;
	private int status;
	private String error;
	private String message;
	private String path;
}
