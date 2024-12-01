package com.notes.thinknotesbackend.config.security;

import com.notes.thinknotesbackend.config.filter.CustomLoggingFilter;
import com.notes.thinknotesbackend.config.filter.UserAgentFilter;
import com.notes.thinknotesbackend.entity.Role;
import com.notes.thinknotesbackend.entity.User;
import com.notes.thinknotesbackend.repository.RoleRepository;
import com.notes.thinknotesbackend.repository.UserRepository;
import com.notes.thinknotesbackend.util.AppRole;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;


import java.time.LocalDate;
import java.time.LocalDateTime;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true,jsr250Enabled = true,securedEnabled = true)
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        //        http.csrf(csrf->csrf.disable());
        http.csrf(csrf ->csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/auth/public/**"));
         http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/public/**").permitAll()  // any request that has public route will not get authenticated like /public/signup  and /public/signin
//                .requestMatchers("/api/private/**").denyAll()
                 .requestMatchers("/api/csrf-token").permitAll()
                .anyRequest().authenticated());
//        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());

        http.addFilterBefore(new CustomLoggingFilter(), UsernamePasswordAuthenticationFilter.class);
//        http.addFilterAfter(new RequestValidationFilter(), CustomLoggingFilter.class);
        http.addFilterBefore(new UserAgentFilter(),CustomLoggingFilter.class);


        http.sessionManagement((session) -> {session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);});

        return http.build();
    }


    @Bean
    public CommandLineRunner initializeData(RoleRepository roleRepository, UserRepository userRepository,PasswordEncoder passwordEncoder) {
        return args -> {
//            Role Creation
            Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER).orElseGet(()->roleRepository.save(new Role(AppRole.ROLE_USER)));
            Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN).orElseGet(()->roleRepository.save(new Role(AppRole.ROLE_ADMIN)));
//            User Creation
            if(!userRepository.existsByUserName("user1")){
                User user1 = new User("user1","user1@sample.com",passwordEncoder.encode("user20"));
                user1.setEnabled(true);
                user1.setAccountNonExpired(true);
                user1.setCredentialsNonExpired(true);
                user1.setAccountNonLocked(false);
                user1.setCreatedDate(LocalDateTime.now());
                user1.setTwoFactorEnabled(false);
                user1.setSignUpMethod("email");
                user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
                user1.setRole(userRole);
                userRepository.save(user1);
            }
            if(!userRepository.existsByUserName("admin")){
                User admin = new User("admin","admin@sample.com",passwordEncoder.encode("admin22"));
                admin.setEnabled(true);
                admin.setAccountNonExpired(true);
                admin.setCredentialsNonExpired(true);
                admin.setAccountNonLocked(false);
                admin.setCreatedDate(LocalDateTime.now());
                admin.setTwoFactorEnabled(false);
                admin.setSignUpMethod("email");
                admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
                admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
                admin.setRole(adminRole);
                userRepository.save(admin);
            }
        };
    }
}
