package demo;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

public class OAuth2AuthenticationFilter extends
		AbstractAuthenticationProcessingFilter {
	
	OpenIDConnectDiscoveryOAuth2Configuration config;
	
	public OAuth2AuthenticationFilter(OpenIDConnectDiscoveryOAuth2Configuration config) {
		super("/login/oidc");
		this.config = config;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException,
			IOException, ServletException {
		AuthenticationManager manager = getAuthenticationManager();
		
		AuthorizationCodeResourceDetails details = config.createRequest();
		
		
		DefaultAccessTokenRequest oauthRequest = new DefaultAccessTokenRequest(request.getParameterMap());
		String uri = ServletUriComponentsBuilder
				.fromRequest(request)
				.replacePath(request.getContextPath())
				.path("/login/oidc")
				.toUriString();
		oauthRequest.setCurrentUri(uri);
		oauthRequest.setStateKey((String) request.getSession().getAttribute("STATE_KEY"));
		oauthRequest.setPreservedState( request.getSession().getAttribute("STATE_VALUE"));
		
		DefaultOAuth2ClientContext context = new DefaultOAuth2ClientContext(oauthRequest);

		// FIXME this needs to be corrected (don't populate from the request as that means it is always the same which doesn't protect on CSRF)
		context.setPreservedState(oauthRequest.getStateKey(), oauthRequest.getPreservedState());

		OAuth2RestTemplate rest = new OAuth2RestTemplate(details, context);
		
		OAuth2AccessToken accessToken = rest.getAccessToken();
		
		String userInfoPath = config.getDiscovery().getUserinfoEndpoint();
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(accessToken);
		rest.getOAuth2ClientContext().setAccessToken(token);
		
		// FIXME need concrete object here
		Map<String,String> map = rest.getForEntity(userInfoPath, Map.class).getBody();

		OAuth2AuthenticationToken oauthAuthentication = new OAuth2AuthenticationToken(accessToken, map);
		oauthAuthentication.setAuthenticated(true);
		return oauthAuthentication;
	}

}
