package com.moussi.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import com.moussi.web.controller.AuthenticationService;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	DataSource dataSource;
	@Autowired
	AuthenticationService customUserDetailsService;

	@Autowired
	public void configAuthentication(AuthenticationManagerBuilder auth)
			throws Exception {

		auth.userDetailsService(customUserDetailsService);
		// auth.jdbcAuthentication().dataSource(dataSource)
		// .usersByUsernameQuery("select username,password, enabled from users where username=?")
		// .authoritiesByUsernameQuery("select username, role from user_roles where username=?");
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf()
				.disable()
				.authorizeRequests()
				.antMatchers("/admin/**")
				.access("hasRole('ROLE_ADMIN')")
				.antMatchers("/admin/update**")
				.access("hasRole('ROLE_ADMIN')")
				.and()
				.formLogin()
				.successHandler(savedRequestAwareAuthenticationSuccessHandler())
				.loginPage("/login").failureUrl("/login?error")
				.loginProcessingUrl("/auth/login_check")
				.usernameParameter("username").passwordParameter("password")
				.and().logout().logoutUrl("/logout")
				.logoutSuccessUrl("/login?logout").and().rememberMe()
			    .rememberMeServices(rememberMeServices());
//				.tokenRepository(persistentTokenRepository())
//				.tokenValiditySeconds(1209600);
	}

	@Bean
	public PersistentTokenRepository persistentTokenRepository() {
		JdbcTokenRepositoryImpl db = new JdbcTokenRepositoryImpl();
		db.setDataSource(dataSource);
		return db;
	}
	
	@Bean   
	  public AbstractRememberMeServices rememberMeServices() {
	      PersistentTokenBasedRememberMeServices rememberMeServices =
	          new PersistentTokenBasedRememberMeServices("AppKey",customUserDetailsService,persistentTokenRepository());
	      rememberMeServices.setAlwaysRemember(true);
	      //rememberMeServices.setTokenLength(1209600);
	      rememberMeServices.setCookieName("remember-me-posc");
	      rememberMeServices.setTokenValiditySeconds(1209600);
	      return rememberMeServices;
	  }
	  
	

	@Bean
	public SavedRequestAwareAuthenticationSuccessHandler savedRequestAwareAuthenticationSuccessHandler() {
		SavedRequestAwareAuthenticationSuccessHandler auth = new SavedRequestAwareAuthenticationSuccessHandler();
		auth.setTargetUrlParameter("targetUrl");
		return auth;
	}

}