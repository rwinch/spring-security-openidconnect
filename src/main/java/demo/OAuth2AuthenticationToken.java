package demo;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {
	
	private OAuth2AccessToken token;
	
	private Object details;

	public OAuth2AuthenticationToken(
			OAuth2AccessToken token, Object details) {
		super(null);
		this.token = token;
		this.details = details;
	}

	@Override
	public Object getCredentials() {
		return token;
	}

	@Override
	public Object getPrincipal() {
		return details;
	}
}