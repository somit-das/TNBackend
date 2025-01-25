package com.notes.thinknotesbackend.repository;

import com.notes.thinknotesbackend.entity.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByUserName(String username);

    Boolean existsByUserName(String username);
    Boolean existsByEmail(String email);

    Optional<User> findByEmail(String email);
    
}
