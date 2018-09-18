package net.prasenjit.identity.service.openid;

import org.springframework.stereotype.Service;

import com.nimbusds.oauth2.sdk.client.ClientDeleteRequest;
import com.nimbusds.oauth2.sdk.client.ClientReadRequest;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientUpdateRequest;

@Service
public class DynamicRegistrationService {

	public ClientRegistrationResponse registerClient(OIDCClientRegistrationRequest request) {
		// TODO Auto-generated method stub
		return null;
	}

	public ClientRegistrationResponse updateClient(String clientID, OIDCClientUpdateRequest request) {
		// TODO Auto-generated method stub
		return null;
	}

	public ClientRegistrationResponse readClient(String clientID, ClientReadRequest request) {
		// TODO Auto-generated method stub
		return null;
	}

	public ClientRegistrationResponse deleteClient(String clientID, ClientDeleteRequest request) {
		// TODO Auto-generated method stub
		return null;
	}

}
