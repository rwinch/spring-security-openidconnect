package demo;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

public class OAuth2AuthenticationFilter extends
		AbstractAuthenticationProcessingFilter {
	
	OpenIDConnectDiscoveryOAuth2Configuration config;
	
	public OAuth2AuthenticationFilter(OpenIDConnectDiscoveryOAuth2Configuration config) {
		super("/login/oidc");
		this.config = config;
		
		SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		successHandler.setRedirectStrategy(new AjaxRedirectStrategy());
		setAuthenticationSuccessHandler(successHandler);
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#attemptAuthentication(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	/* (non-Javadoc)
	 * @see org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#attemptAuthentication(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException,
			IOException, ServletException {
		
		String tokenInfoUrl = "https://www.googleapis.com/oauth2/v3/tokeninfo";
		RestTemplate rest = new RestTemplate();
				
		BearerTokenExtractor extractor = new BearerTokenExtractor();
		
		Authentication token = extractor.extract(request);
		
		if(token == null) {
			return null;
		}
		
		URI uri = UriComponentsBuilder
			.fromHttpUrl(tokenInfoUrl)
			.queryParam("id_token", token.getPrincipal())
			.build()
			.encode()
			.toUri();
		
		
		// FIXME need concrete object here
		Map<String,String> map = rest.getForEntity(uri, Map.class).getBody();

		OAuth2AuthenticationToken oauthAuthentication = new OAuth2AuthenticationToken(token.getName(), map);
		oauthAuthentication.setAuthenticated(true);
		return oauthAuthentication;
	}

	static class AjaxRedirectStrategy implements RedirectStrategy {

		@Override
		public void sendRedirect(HttpServletRequest request,
				HttpServletResponse response, String url) throws IOException {
			response.getWriter().write(url);
		}
	}
}
