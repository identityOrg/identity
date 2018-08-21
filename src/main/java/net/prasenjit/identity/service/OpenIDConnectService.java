package net.prasenjit.identity.service;

import com.nimbusds.oauth2.sdk.AuthorizationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import net.prasenjit.identity.model.AuthorizationModel;
import org.springframework.stereotype.Service;

@Service
public class OpenIDConnectService {
    public AuthorizationResponse processAuthentication(AuthorizationModel authorizationModel, AuthenticationRequest authenticationRequest) {

        return null;
    }
}
