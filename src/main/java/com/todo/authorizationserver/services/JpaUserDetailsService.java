package com.todo.authorizationserver.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.todo.authorizationserver.repositories.UserRepository;

@Service
public class JpaUserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

	@Autowired
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
