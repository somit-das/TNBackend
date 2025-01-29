package com.notes.thinknotesbackend.service;

import com.notes.thinknotesbackend.dto.UserDTO;
import com.notes.thinknotesbackend.entity.Role;
import com.notes.thinknotesbackend.entity.User;

import java.util.List;
import java.util.Optional;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;

@Service
public interface UserService {
	
	User save(User user);
	List<User> getAllUsers();
	
	    void updateUserRole(Long userId, String roleName);

	    UserDTO getUserById(Long id);

	    User findByUsername(String username);


	    Boolean existsByUserName(String username);
		Boolean existsByEmail(String email);
	    List<Role> getAllRoles();
	void updateAccountLockStatus(Long userId, boolean lockStatus);

	void updateAccountExpiryStatus(Long userId, boolean expiryStatus);


	void updateAccountEnabledStatus(Long userId, boolean enabled);

	void updateCredentialsExpiryStatus(Long userId, boolean expiryStatus);

	void updatePassword(Long userId, String password);

    Optional<User> findByEmail(String email);

	User oAuth2RegisterUser(User user);

	GoogleAuthenticatorKey generate2FASecret(Long userId);

	boolean validate2FASecret(Long userId, int code);

	void enable2FA(Long userId);

	void disable2FA(Long userId);
}
