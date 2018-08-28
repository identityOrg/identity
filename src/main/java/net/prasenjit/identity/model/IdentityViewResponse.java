package net.prasenjit.identity.model;

import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ResponseMode;
import lombok.Getter;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

public class IdentityViewResponse extends AuthorizationResponse {

    @Getter
    private ViewType viewType;
    @Getter
    private ErrorObject errorObject;
    @Getter
    private Map<String, String> attributes = new HashMap<>();

    public IdentityViewResponse(ViewType viewType) {
        super(URI.create("http://localhost"), null, null);
        this.viewType = viewType;
    }

    public IdentityViewResponse(ErrorObject errorObject) {
        this(ViewType.ERROR);
        this.errorObject = errorObject;
    }

    @Override
    public ResponseMode impliedResponseMode() {
        return null;
    }

    @Override
    public Map<String, String> toParameters() {
        return null;
    }

    @Override
    public boolean indicatesSuccess() {
        return false;
    }

    public enum ViewType {
        LOGIN("redirect:/login"),
        CONSENT("authorize-new"),
        ERROR("req-error");

        @Getter
        private final String viewName;

        ViewType(String viewName) {
            this.viewName = viewName;
        }
    }
}
