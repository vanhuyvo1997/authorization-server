package com.todo.authorizationserver.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.todo.authorizationserver.models.Client;

public interface ClientRepository extends JpaRepository<Client, String> {
	Optional<Client> findByClientId(String clientId);
}