package com.zkteco.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import com.zkteco.security.user.Permission;
import com.zkteco.security.user.Role;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {
	
	private static final String[] WHITE_LIST_URL = {"/api/v1/auth/**"};
	private final JwtAuthenticationFilter jwtAuthFilter;
	private final AuthenticationProvider authenticationProvider;
	private final LogoutHandler logoutHandler;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
				.authorizeHttpRequests((requests) -> {
					requests.requestMatchers(WHITE_LIST_URL).permitAll()
					
					.requestMatchers("/api/v1/management/**").hasAnyRole(Role.ADMIN.name(),Role.MANAGER.name())
					
					.requestMatchers(HttpMethod.GET,"/api/v1/management/**").hasAnyAuthority(Permission.ADMIN_READ.name(),Permission.MANAGER_READ.name())
					.requestMatchers(HttpMethod.POST,"/api/v1/management/**").hasAnyAuthority(Permission.ADMIN_CREATE.name(),Permission.MANAGER_CREATE.name())
					.requestMatchers(HttpMethod.PUT,"/api/v1/management/**").hasAnyAuthority(Permission.ADMIN_UPDATE.name(),Permission.MANAGER_UPDATE.name())
					.requestMatchers(HttpMethod.DELETE,"/api/v1/management/**").hasAnyAuthority(Permission.ADMIN_DELETE.name(),Permission.MANAGER_DELETE.name())
					
					/*
					 * requests.requestMatchers("/api/v1/admin/**").hasRole(Role.ADMIN.name());
					 * 
					 * 
					 * requests.requestMatchers(HttpMethod.GET,"/api/v1/admin/**").hasAuthority(
					 * Permission.ADMIN_READ.name());
					 * requests.requestMatchers(HttpMethod.POST,"/api/v1/admin/**").hasAuthority(
					 * Permission.ADMIN_CREATE.name());
					 * requests.requestMatchers(HttpMethod.PUT,"/api/v1/admin/**").hasAuthority(
					 * Permission.ADMIN_UPDATE.name());
					 * requests.requestMatchers(HttpMethod.DELETE,"/api/v1/admin/**").hasAuthority(
					 * Permission.ADMIN_DELETE.name());
					 */
					.anyRequest().authenticated();
					
				}).sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.authenticationProvider(authenticationProvider)
				.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> httpSecurityExceptionHandlingConfigurer
						.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
				.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class).logout((logout)->logout.logoutUrl("/api/v1/auth/logout")
						.addLogoutHandler(logoutHandler)
						.logoutSuccessHandler((request, response, authentication)->SecurityContextHolder.clearContext())
						);

		/*
		 * http .authorizeHttpRequests() .requestMatchers("/api/v1/auth/**")
		 * .permitAll()
		 * .requestMatchers("/api/v1/management/**").hasAnyRole(com.zkteco.security.user
		 * .Role.ADMIN) .anyRequest() .authenticated() .and() .sessionManagement()
		 * .sessionCreationPolicy(SessionCreationPolicy.STATELESS) .and()
		 * .authenticationProvider(authentcationProvider)
		 * .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
		 */
		return http.build();
	}

}
