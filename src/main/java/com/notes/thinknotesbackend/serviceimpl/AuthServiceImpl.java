package com.notes.thinknotesbackend.serviceimpl;
import com.notes.thinknotesbackend.config.security.customuserdetails.UserDetailsImpl;
import com.notes.thinknotesbackend.config.security.util.JwtUtils;
import com.notes.thinknotesbackend.config.security.util.request.LoginRequest;
import com.notes.thinknotesbackend.config.security.util.request.SignUpRequest;
import com.notes.thinknotesbackend.config.security.util.response.LoginResponse;
import com.notes.thinknotesbackend.config.security.util.response.MessageResponse;
import com.notes.thinknotesbackend.config.security.util.response.UserInfoResponse;
import com.notes.thinknotesbackend.entity.PasswordResetToken;
import com.notes.thinknotesbackend.entity.Role;
import com.notes.thinknotesbackend.entity.User;
import com.notes.thinknotesbackend.repository.PasswordResetTokenRepository;
import com.notes.thinknotesbackend.repository.RoleRepository;
import com.notes.thinknotesbackend.service.AuthService;
import com.notes.thinknotesbackend.service.EmailService;
import com.notes.thinknotesbackend.service.UserService;
import com.notes.thinknotesbackend.util.AppRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthServiceImpl implements AuthService {

    @Value("${frontend.url}")
    String frontendUrl;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private EmailService emailService;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Override
    public ResponseEntity<?> authenticateUser(LoginRequest loginRequest) {
    	Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

//      Set the authentication
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // Collect roles from the UserDetails
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        // Prepare the response body, now including the JWT token directly in the body
        LoginResponse response = new LoginResponse(userDetails.getUsername(),
                roles, jwtToken);

        // Return the response entity with the JWT token included in the response body
        return ResponseEntity.ok(response);
    }

    @Override
    public ResponseEntity<?> registerUser(SignUpRequest signUpRequest) {
    	if (userService.existsByUserName(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userService.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                passwordEncoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Role role;

        if (strRoles == null || strRoles.isEmpty()) {
            role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        } else {
            String roleStr = strRoles.iterator().next();
            if (roleStr.equals("admin")) {
                role = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            } else {
                role = roleRepository.findByRoleName(AppRole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            }

            user.setAccountNonLocked(true);
            user.setAccountNonExpired(true);
            user.setCredentialsNonExpired(true);
            user.setEnabled(true);
            user.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user.setTwoFactorEnabled(false);
            user.setSignUpMethod("email");
        }
        user.setRole(role);
        userService.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @Override
    public ResponseEntity<?> getUserDetails(UserDetails userDetails) {
    	User user = userService.findByUsername(userDetails.getUsername());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        UserInfoResponse response = new UserInfoResponse(
                user.getUserId(),
                user.getUserName(),
                user.getEmail(),
                user.isAccountNonLocked(),
                user.isAccountNonExpired(),
                user.isCredentialsNonExpired(),
                user.isEnabled(),
                user.getCredentialsExpiryDate(),
                user.getAccountExpiryDate(),
                user.isTwoFactorEnabled(),
                roles
        );

        return ResponseEntity.ok().body(response);
    }

    @Override
    public String getUserName(UserDetails userDetails) {


    	return (userDetails != null) ? userDetails.getUsername() : "";
    }
    @Override
    public void generatePasswordResetToken(String email) {
        User user = userService.findByEmail(email).orElseThrow(() -> new RuntimeException("Error: User not found!"));
        String token = UUID.randomUUID().toString();
        Instant expiryDate = Instant.now().plus(5, ChronoUnit.MINUTES);
        PasswordResetToken resetToken = new PasswordResetToken(token,expiryDate,user);
        passwordResetTokenRepository.save(resetToken);

        String resetUrl= frontendUrl+"/reset-password?token="+token;
        System.out.println(resetUrl);
//        Send Email To User
        emailService.sendPasswordResetEmail(user.getUserName(),user.getEmail(),resetUrl );
    }

    @Override
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token).orElseThrow(()-> new RuntimeException("Error: Invalid Password Reset Token!"));
        if(resetToken.isUsed()){
            throw new RuntimeException("Password Reset Token has already used!");
        }
        if(resetToken.getExpiryDate().isBefore(Instant.now())){
            throw new RuntimeException("Password Reset Token has expired!");
        }
        User user =  resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userService.save(user);

        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);
    }
}
