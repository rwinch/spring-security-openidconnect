package demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebMvcSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	OpenIDConnectDiscoveryOAuth2Configuration config;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.addFilterBefore(oauthFilter(), UsernamePasswordAuthenticationFilter.class)
			.exceptionHandling()
				.authenticationEntryPoint(new OAuth2AuthenticationEntryPoint(config))
				.and()
			.authorizeRequests()
				.anyRequest().authenticated();
	}
	
	@Bean
	public OAuth2AuthenticationFilter oauthFilter() {
		OAuth2AuthenticationFilter filter = new OAuth2AuthenticationFilter(config);
		filter.setAuthenticationManager(authenticationManager);
		return filter;
	}
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) {
		auth
			.authenticationProvider(new OAuth2AuthenticationProvider());
	}
}