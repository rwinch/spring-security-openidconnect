package demo;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

public class OAuth2AuthenticationEntryPoint implements AuthenticationEntryPoint {
	RedirectStrategy redirect = new DefaultRedirectStrategy();
	OpenIDConnectDiscoveryOAuth2Configuration config;

	public OAuth2AuthenticationEntryPoint(
			OpenIDConnectDiscoveryOAuth2Configuration config) {
		super();
		this.config = config;
	}



	@Override
	public void commence(HttpServletRequest request,
			HttpServletResponse response, AuthenticationException authException)
			throws IOException, ServletException {
		
		AuthorizationCodeResourceDetails details = config.createRequest();
		
		DefaultAccessTokenRequest oauthRequest = new DefaultAccessTokenRequest();
		String uri = ServletUriComponentsBuilder
				.fromRequest(request)
				.replacePath(request.getContextPath())
				.path("/login/oidc")
				.toUriString();
		oauthRequest.setCurrentUri(uri);
		
		DefaultOAuth2ClientContext context = new DefaultOAuth2ClientContext(oauthRequest);

		OAuth2RestTemplate rest = new OAuth2RestTemplate(details, context);
		try {
			rest.getAccessToken();
		} catch(UserRedirectRequiredException e) {
			String redirectUri = e.getRedirectUri();
			UriComponentsBuilder builder = UriComponentsBuilder
					.fromHttpUrl(redirectUri);
			Map<String, String> requestParams = e.getRequestParams();
			for (Map.Entry<String, String> param : requestParams.entrySet()) {
				builder.queryParam(param.getKey(), param.getValue());
			}

			if (e.getStateKey() != null) {
				builder.queryParam("state", e.getStateKey());
				request.getSession().setAttribute("STATE_KEY", e.getStateKey());
				request.getSession().setAttribute("STATE_VALUE", e.getStateToPreserve());
			}
			redirect.sendRedirect(request, response, builder.toUriString());
		}
	}
}