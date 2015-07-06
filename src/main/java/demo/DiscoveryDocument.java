package demo;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DiscoveryDocument {
	private String issuer;

	@JsonProperty("authorization_endpoint")
	private String authorizationEndpoint;
	
	@JsonProperty("token_endpoint")
	private String tokenEndpoint;
	
	@JsonProperty("userinfo_endpoint")
	private String userinfoEndpoint;
	
	@JsonProperty("revocation_endpoint")
	private String revocationEndpoint;
	
	@JsonProperty("jwks_uri")
	private String jwksUri;

	public String getIssuer() {
		return issuer;
	}

	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	public String getAuthorizationEndpoint() {
		return authorizationEndpoint;
	}

	public void setAuthorizationEndpoint(String authorizationEndpoint) {
		this.authorizationEndpoint = authorizationEndpoint;
	}

	public String getTokenEndpoint() {
		return tokenEndpoint;
	}

	public void setTokenEndpoint(String tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
	}

	public String getUserinfoEndpoint() {
		return userinfoEndpoint;
	}

	public void setUserinfoEndpoint(String userinfoEndpoint) {
		this.userinfoEndpoint = userinfoEndpoint;
	}

	public String getRevocationEndpoint() {
		return revocationEndpoint;
	}

	public void setRevocationEndpoint(String revocationEndpoint) {
		this.revocationEndpoint = revocationEndpoint;
	}

	public String getJwksUri() {
		return jwksUri;
	}

	public void setJwksUri(String jwksUri) {
		this.jwksUri = jwksUri;
	}
	
	
}
