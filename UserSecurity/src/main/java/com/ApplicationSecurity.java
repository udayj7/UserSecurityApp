package com;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class ApplicationSecurity {

	@Bean
	public InMemoryUserDetailsManager userDetailsService() {
		UserDetails user = User.withUsername("apple").password(passwordEncoder().encode("bat")).roles("USER").build();
		UserDetails user1 = User.withUsername("king").password(passwordEncoder().encode("king")).roles("USER", "ADMIN")
				.build();
		return new InMemoryUserDetailsManager(user, user1);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
//	@Bean
//	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//		http.authorizeRequests(authorize -> 
//			authorize.requestMatchers("/user").permitAll()
//			.requestMatchers("/admin").hasAnyRole("ADMIN")
//			.requestMatchers("/merchant").hasAnyRole("ADMIN", "USER"))
//			.formLogin();
//		return http.build();
//	}
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.csrf().disable()
				.authorizeHttpRequests().requestMatchers("/user").permitAll().and()

				.authorizeHttpRequests().requestMatchers("/admin").hasAnyRole("ADMIN").anyRequest()
				.authenticated().and()
				.authorizeHttpRequests().requestMatchers("/merchant").hasAnyRole("ADMIN", "USER").anyRequest()
				.authenticated().and()

				.formLogin()// Add Customer Details only
//						.httpBasic()//Add flightBooking Details
				.and().build();

	}
}
