package com.todo.authorizationserver;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import jakarta.annotation.PostConstruct;

@SpringBootApplication
public class AuthorizationServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthorizationServerApplication.class, args);
	}

	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@PostConstruct
	public void initStartupClient() {
		RegisteredClient mytaskClient = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("mytask-client")
				.clientSecret(passwordEncoder.encode("this-is-secret"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://localhost:3000/api/auth/callback/mytask-client")
				.postLogoutRedirectUri("http://localhost:3000")
				.scope("read").scope("write")
				.scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE).scope(OidcScopes.EMAIL)
				.clientSettings(
						ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		registeredClientRepository.save(mytaskClient);
	}
}
