package com.todo.authorizationserver.services;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.todo.authorizationserver.repositories.UserRepository;

@Service
public class JpaUserDetailsService implements UserDetailsService {

	
	private final UserRepository userRepository;
	
	public JpaUserDetailsService(UserRepository userRepository) {
		super();
		this.userRepository = userRepository;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		var optUser = userRepository.findByEmail(username);
		if(optUser.isPresent()) {
			return optUser.get();
		} 
		throw new UsernameNotFoundException(username +  " is not found");
	}

}
