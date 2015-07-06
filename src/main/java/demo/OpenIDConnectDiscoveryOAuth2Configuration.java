package demo;

import java.util.Arrays;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
@ConfigurationProperties(prefix="spring.security.oauth2.google")
public class OpenIDConnectDiscoveryOAuth2Configuration {
	private String discoveryUrl;
	
	private String clientId;
	
	private String clientSecret;

	public String getDiscoveryUrl() {
		return discoveryUrl;
	}

	public void setDiscoveryUrl(String discoveryUrl) {
		this.discoveryUrl = discoveryUrl;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}
	
	public DiscoveryDocument getDiscovery() {
		RestTemplate rest = new RestTemplate();
		
		return rest.getForEntity(discoveryUrl, DiscoveryDocument.class).getBody();
	}
	
	public AuthorizationCodeResourceDetails createRequest() {
		DiscoveryDocument document = getDiscovery();
		
		AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
		details.setAccessTokenUri(document.getTokenEndpoint());
		details.setUserAuthorizationUri(document.getAuthorizationEndpoint());
		details.setClientId(clientId);
		details.setClientSecret(clientSecret);
		details.setScope(Arrays.asList("openid"));
		return details;
	}
}
