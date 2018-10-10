package net.prasenjit.identity.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.stereotype.Service;

import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserInfoService {
	
	private final AuthenticationManager authenticationManager;

	public UserInfoResponse retrieveUserInfo(UserInfoRequest request) {
		AccessToken accessToken = request.getAccessToken();
		if(accessToken==null || !(accessToken instanceof BearerAccessToken)) {
			BearerTokenError bearerError = BearerTokenError.INVALID_TOKEN;
			return new UserInfoErrorResponse(bearerError);
		}
		UserInfo claimsSet = new UserInfo(new Subject("admin"));
		UserInfoResponse response = new UserInfoSuccessResponse(claimsSet);
		return response;
	}

}
