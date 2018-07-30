package net.prasenjit.identity.security;

public interface OAuthError {
    String INVALID_REQUEST = "invalid_request";
    String UNAUTHORIZED_REQUEST = "unauthorized_client";
    String ACCESS_DENIED = "access_denied";
    String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    String INVALID_SCOPE = "invalid_scope";
    String SERVER_ERROR = "server_error";
    String TEMPORARILY_UNAVAILABLE = "temporarily_unavailable";
    String LOGIN_REQUIRED = "login_required";
    String INTERACTION_REQUIRED = "interaction_required";
}
