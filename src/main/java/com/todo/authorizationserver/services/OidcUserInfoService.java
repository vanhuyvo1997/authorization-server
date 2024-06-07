package com.todo.authorizationserver.services;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;

import com.todo.authorizationserver.repositories.UserRepository;

@Service
public class OidcUserInfoService {

	public OidcUserInfoService(UserRepository userInfoRepository) {
		this.userInfoRepository = userInfoRepository;
	}

	private final UserRepository userInfoRepository;

	public OidcUserInfo loadUser(String username) {
		var optUser = this.userInfoRepository.findByEmail(username);
		if(optUser.isEmpty()) throw new UsernameNotFoundException(username + " not found");
		var user = optUser.get();
		
		return OidcUserInfo.builder()
				.subject(username)
				.name(user.getFirstName() + " " + user.getLastName())
				.givenName(user.getFirstName())
				.familyName(user.getLastName())
				.preferredUsername(username)
				.picture(user.getAvatar())
				.email(username)
				.build();
	}
}
