package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.*;
import net.prasenjit.identity.exception.OAuthException;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.oauth.GrantType;
import net.prasenjit.identity.oauth.OAuthError;
import net.prasenjit.identity.repository.AuthorizationCodeRepository;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.RefreshTokenRepository;
import net.prasenjit.identity.repository.UserRepository;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

//@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service {

	private final AuthenticationManager authenticationManager;
	private final CodeFactory codeFactory;
	private final ClientRepository clientRepository;
	private final AuthorizationCodeRepository codeRepository;
	private final UserRepository userRepository;
	private final RefreshTokenRepository refreshTokenRepository;

	public OAuthToken processPasswordGrant(Client client, String username, String password, String requestedScope) {
		if (!client.supportsGrant(GrantType.PASSWORD)) {
			throw new OAuthException("invalid_grant", "Unsupported grant");
		}
		Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
		try {
			authentication = authenticationManager.authenticate(authentication);
		} catch (BadCredentialsException e) {
			throw new OAuthException("access_denied", "user authentication failed");
		}
		String filteredScopes = filterScope(client.getApprovedScopes(), requestedScope);
		AccessToken accessToken = codeFactory.createAccessToken((User) authentication.getPrincipal(),
				client.getClientId(), client.getAccessTokenValidity(), filteredScopes);
		RefreshToken refreshToken = null;
		if (!client.supportsGrant(GrantType.REFRESH_TOKEN)) {
			refreshToken = codeFactory.createRefreshToken(client.getClientId(), username, filteredScopes,
					client.getRefreshTokenValidity());
		}
		return codeFactory.createOAuthToken(accessToken, refreshToken);
	}

	public OAuthToken processClientCredentialsGrant(Client client, String scope) {
		if (!client.supportsGrant(GrantType.CLIENT_CREDENTIALS)) {
			throw new OAuthException("invalid_grant", "Unsupported grant");
		}
		String filteredScope = filterScope(client.getApprovedScopes(), scope);
		AccessToken accessToken = codeFactory.createAccessToken(client, client.getClientId(),
				client.getAccessTokenValidity(), filteredScope);
		return codeFactory.createOAuthToken(accessToken, null);
	}

	public AuthorizationModel validateAuthorizationGrant(String responseType, User principal, String clientId,
			String scope, String state, String redirectUri) {
		AuthorizationModel authorizationModel = new AuthorizationModel();
		authorizationModel.setState(state);
		authorizationModel.setUser(principal);
		authorizationModel.setValid(false);
		authorizationModel.setResponseType(responseType);
		authorizationModel.setRedirectUri(redirectUri);

		if (clientId == null) {
			authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
			authorizationModel.setErrorDescription("Client id not specified");
			return authorizationModel;
		}

		Optional<Client> client = clientRepository.findById(clientId);

		if (!client.isPresent()) {
			authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
			authorizationModel.setErrorDescription("Provided clientId is invalid");
			return authorizationModel;
		} else {
			authorizationModel.setClient(client.get());
			if (redirectUri != null && !client.get().getRedirectUri().equals(redirectUri)) {
				authorizationModel.setRedirectUri(client.get().getRedirectUri());
				authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
				authorizationModel.setErrorDescription("Redirect URL doesn't match");
				return authorizationModel;
			}
			
			if ("code".equals(responseType)) {
				if (!client.get().supportsGrant(GrantType.AUTHORIZATION_CODE)) {
					authorizationModel.setErrorCode(OAuthError.ACCESS_DENIED);
					authorizationModel.setErrorDescription("Client is not authorized for the specifies response type");
					return authorizationModel;
				}
				Map<String, Boolean> scopeToApprove = filterScopeToMap(client.get().getApprovedScopes(), scope);

				authorizationModel.setClient(client.get());
				authorizationModel.setUser(principal);
				authorizationModel.setFilteredScopes(scopeToApprove);
				authorizationModel.setValid(true);
				return authorizationModel;
			} else if ("token".equals(responseType)) {
				if (!client.get().supportsGrant(GrantType.IMPLICIT)) {
					authorizationModel.setErrorCode(OAuthError.ACCESS_DENIED);
					authorizationModel.setErrorDescription("Client is not authorized for the specifies response type");
					return authorizationModel;
				}
				Map<String, Boolean> scopeToApprove = filterScopeToMap(client.get().getApprovedScopes(), scope);

				authorizationModel.setClient(client.get());
				authorizationModel.setUser(principal);
				authorizationModel.setFilteredScopes(scopeToApprove);
				authorizationModel.setValid(true);
				return authorizationModel;
			} else {
				authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
				authorizationModel.setErrorDescription("Unsupported response type");
				return authorizationModel;
			}

		}
	}

	public AuthorizationModel processAuthorizationOrImplicitGrant(AuthorizationModel authorizationModel) {
		if (authorizationModel.isValid()) {
			Optional<Client> client = clientRepository.findById(authorizationModel.getClient().getClientId());

			if (!client.isPresent()) {
				authorizationModel.setValid(false);
				authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
				authorizationModel.setErrorDescription("Provided clientId is invalid");
				return authorizationModel;
			} else {
				authorizationModel.setClient(client.get());
				List<String> approvedScope = authorizationModel.getFilteredScopes().entrySet().stream()
						.filter(Map.Entry::getValue).map(Map.Entry::getKey).collect(Collectors.toList());
				if ("code".equals(authorizationModel.getResponseType())) {
					AuthorizationCode authorizationCode = codeFactory.createAuthorizationCode(
							client.get().getClientId(), authorizationModel.getRedirectUri(),
							StringUtils.collectionToDelimitedString(approvedScope, " "),
							authorizationModel.getUser().getUsername(), authorizationModel.getState(),
							Duration.ofMinutes(10));
					authorizationModel.setAuthorizationCode(authorizationCode);
					if (!StringUtils.hasText(authorizationModel.getRedirectUri())) {
						authorizationModel.setRedirectUri(client.get().getRedirectUri());
					}
					return authorizationModel;
				} else if ("token".equals(authorizationModel.getResponseType())) {
					AccessToken accessToken = codeFactory.createAccessToken(authorizationModel.getUser(),
							client.get().getClientId(), client.get().getAccessTokenValidity(),
							StringUtils.collectionToDelimitedString(approvedScope, " "));
					authorizationModel.setAccessToken(accessToken);
					return authorizationModel;
				} else {
					authorizationModel.setErrorCode(OAuthError.UNSUPPORTED_RESPONSE_TYPE);
					authorizationModel.setErrorDescription("Invalid response type");
					authorizationModel.setValid(false);
					return authorizationModel;
				}
			}
		}
		authorizationModel.setErrorCode(OAuthError.UNAUTHORIZED_REQUEST);
		authorizationModel.setErrorDescription("User has denied the access");
		authorizationModel.setValid(false);
		return authorizationModel;
	}

	public OAuthToken processAuthorizationCodeGrantToken(Client client, String code, String redirectUri,
			String clientId) {
		if (client == null) {
			if (clientId == null) {
				throw new OAuthException("invalid_request", "non secure client must specify client_id parameter");
			}
			Optional<Client> optionalClient = clientRepository.findById(clientId);
			if (optionalClient.isPresent()) {
				if (optionalClient.get().isSecureClient()) {
					throw new OAuthException("unauthorized_client", "Secure client must be authenticated");
				} else {
					client = optionalClient.get();
				}
			} else {
				throw new OAuthException("invalid_request", "Client not found for client_id " + clientId);
			}
		}
		if (null == code) {
			throw new OAuthException("invalid_request", "authorization code must be provided");
		} else {
			Optional<AuthorizationCode> authorizationCode = codeRepository.findByAuthorizationCode(code);
			if (authorizationCode.isPresent()) {
				if (!authorizationCode.get().isUsed()) {
					if (authorizationCode.get().getClientId().equals(client.getClientId())) {
						if (!StringUtils.hasText(authorizationCode.get().getReturnUrl())
								|| authorizationCode.get().getReturnUrl().equals(redirectUri)) {
							if (authorizationCode.get().isValid()) {
								authorizationCode.get().setUsed(true);
								Optional<User> associatedUser = userRepository
										.findById(authorizationCode.get().getUsername());
								if (associatedUser.isPresent()) {
									AccessToken accessToken = codeFactory.createAccessToken(associatedUser.get(),
											client.getClientId(), client.getAccessTokenValidity(),
											authorizationCode.get().getScope());
									RefreshToken refreshToken = null;
									if (client.supportsGrant(GrantType.REFRESH_TOKEN)) {
										refreshToken = codeFactory.createRefreshToken(client.getClientId(),
												associatedUser.get().getUsername(), accessToken.getScope(),
												client.getRefreshTokenValidity());
									}
									return codeFactory.createOAuthToken(accessToken, refreshToken);
								}
							}
						}
					}
				}
			}
			throw new OAuthException("invalid_request", "Authorization code invalid");
		}
	}

	public OAuthToken processRefreshTokenGrantToken(Client client, String refreshToken) {
		if (client == null) {
			throw new OAuthException("unauthorized_client", "Client is not authenticated");
		}
		Optional<RefreshToken> tokenOptional = refreshTokenRepository.findById(refreshToken);
		if (tokenOptional.isPresent()) {
			if (tokenOptional.get().isValid()) {
				Optional<User> userOptional = userRepository.findById(tokenOptional.get().getUsername());
				if (userOptional.isPresent()) {
					if (userOptional.get().isValid()) {
						tokenOptional.get().setUsed(true);
						AccessToken accessToken = codeFactory.createAccessToken(userOptional.get(),
								client.getClientId(), client.getAccessTokenValidity(), tokenOptional.get().getScope());
						RefreshToken refreshToken1 = codeFactory.createRefreshToken(client.getClientId(),
								userOptional.get().getUsername(), tokenOptional.get().getScope(),
								client.getRefreshTokenValidity());
						return codeFactory.createOAuthToken(accessToken, refreshToken1);
					} else {
						throw new OAuthException("access_denied", "Invalid user");
					}
				} else {
					throw new OAuthException("access_denied", "Associated user not found");
				}
			} else {
				throw new OAuthException("access_denied", "Expired refresh token");
			}
		}
		throw new OAuthException("access_denied", "Invalid refresh token");
	}

	public String createTokenResponseFragment(AccessToken accessToken, String state) {
		StringBuilder builder = new StringBuilder();
		long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
		builder.append("access_token").append('=').append(accessToken.getAssessToken()).append("token_type").append('=')
				.append("Bearer").append("expires_in").append('=').append(expIn).append("scope").append('=')
				.append(accessToken.getScope()).append("state").append('=').append(state);
		return builder.toString();
	}

	private Map<String, Boolean> filterScopeToMap(String approvedScopes, String requestedScope) {
		String[] approved = StringUtils.delimitedListToStringArray(approvedScopes, " ");
		String[] requested = StringUtils.delimitedListToStringArray(requestedScope, " ");
		if (approved.length == 0) {
			return new HashMap<>();
		}
		if (requested.length == 0) {
			return Stream.of(approved).collect(Collectors.toMap(o -> o, o -> Boolean.TRUE));
		}
		Map<String, Boolean> filteredMap = new HashMap<>();
		for (String r : requested) {
			if (ArrayUtils.contains(approved, r)) {
				filteredMap.put(r, Boolean.TRUE);
			}
		}
		return filteredMap;
	}

	private String filterScope(String approvedScopes, String requestedScope) {
		String[] approved = StringUtils.delimitedListToStringArray(approvedScopes, " ");
		String[] requested = StringUtils.delimitedListToStringArray(requestedScope, " ");
		if (approved.length == 0) {
			return null;
		}
		if (requested.length == 0) {
			return approvedScopes;
		}
		List<String> filtered = new ArrayList<>();
		for (String r : requested) {
			if (ArrayUtils.contains(approved, r)) {
				filtered.add(r);
			}
		}
		return StringUtils.collectionToDelimitedString(filtered, " ");
	}
}