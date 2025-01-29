package com.notes.thinknotesbackend.config.security;

import com.notes.thinknotesbackend.config.filter.CustomLoggingFilter;
import com.notes.thinknotesbackend.config.filter.UserAgentFilter;
import com.notes.thinknotesbackend.config.security.AuthenticationHandlers.OAuth2LoginSuccessHandler;
import com.notes.thinknotesbackend.config.security.exceptionhandler.AuthEntryPoint;
import com.notes.thinknotesbackend.config.security.securityfilter.JwtAuthTokenFilter;
import com.notes.thinknotesbackend.entity.Role;
import com.notes.thinknotesbackend.entity.User;
import com.notes.thinknotesbackend.repository.RoleRepository;
import com.notes.thinknotesbackend.repository.UserRepository;
import com.notes.thinknotesbackend.util.AppRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;


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


    @Autowired
    public AuthEntryPoint unauthorizedHandler;

    @Autowired
    @Lazy
    private OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;

    @Bean
    public JwtAuthTokenFilter jwtAuthTokenFilter() {
        return new JwtAuthTokenFilter();
    }
    

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        //        http.csrf(csrf->csrf.disable());
        http.csrf(csrf ->csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));//http.csrf(): This is configuring the CSRF protection for the HTTP requests. CSRF is a security vulnerability that allows attackers to perform actions on behalf of authenticated users without their consent. By default, Spring Security enables CSRF protection to prevent this. //csrf -> csrf.csrfTokenRepository(): This is chaining a configuration that sets a custom repository for storing and handling the CSRF token. The csrfTokenRepository is responsible for how the CSRF token is stored and transmitted between the client and server.
        //CookieCsrfTokenRepository is a repository that stores the CSRF token in a cookie.  // withHttpOnlyFalse() configures the cookie to be non-HttpOnly. By default, cookies set with HttpOnly cannot be accessed via JavaScript. This option makes the cookie accessible by JavaScript (for scenarios like using it in an AJAX request).//

        http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/auth/public/**")); // you have to disable csrf specially because permitAll() using requestmatcher is only for authentication.
        http.authorizeHttpRequests((requests) -> requests
                 .requestMatchers("/api/admin/**").hasRole("ADMIN")
                 .requestMatchers("/api/public/**").permitAll()  // any request that has public route will not get authenticated like /public/signup  and /public/signin
                 // When you use requestMatchers("/api/public/**").permitAll(), you're explicitly allowing access to the /api/public/** endpoints without any authentication or authorization checks. This includes CSRF protection, meaning CSRF will not be applied to those endpoints by default, because Spring Security treats the request as being "public" and does not require protection for it.
//                .requestMatchers("/api/private/**").denyAll()
                 .requestMatchers("/api/auth/public/**").permitAll() //permitting to access signin and signup page
                 .requestMatchers("/api/csrf-token").permitAll() // permitting to access csrf-token for every state-changing request
                 .requestMatchers("/oauth2/**").permitAll()
                 .anyRequest().authenticated())
                 .oauth2Login(oAuth2Login ->{
                    oAuth2Login.successHandler(oAuth2LoginSuccessHandler);
                });

//      http.formLogin(Customizer.withDefaults());
//      http.httpBasic(Customizer.withDefaults());  //Yes, if you're implementing JWT-based authentication, you typically need to remove or avoid using HTTP Basic Authentication, as they serve different purposes and methods of securing your application. Enabling http.httpBasic() will activate Basic Authentication for all requests, even those protected by your JWT-based security logic.
// This can cause unexpected behavior which is Basic Authentication may prompt for credentials in the browser and it might override or bypass JWT validation

        http.addFilterBefore(new CustomLoggingFilter(), UsernamePasswordAuthenticationFilter.class);
//        http.addFilterAfter(new RequestValidationFilter(), CustomLoggingFilter.class);
        http.addFilterBefore(new UserAgentFilter(),CustomLoggingFilter.class);

        http.exceptionHandling(exception ->exception.authenticationEntryPoint(unauthorizedHandler));
        http.addFilterBefore(jwtAuthTokenFilter(), UsernamePasswordAuthenticationFilter.class); // here JwtAuthTokenFilter added as a bean for jwt authentication
        // unlike before no "new JwtAuthTokenFiler()" is used as i want to make this component reusable
        // it could be autowired like JwtAuthTokenFilter yes but @Bean Allows full customization of bean creation where as @Autowired allow No control over how the bean is created.

//        http.addFilterBefore(new CustomLoggingFilter(),UsernamePasswordAuthenticationFilter.class);
//        http.addFilterBefore(new UserAgentFilter(),CustomLoggingFilter.class);
//        http.addFilterAfter(new RequestValidationFilter(), AuthorizationFilter.class);
//        http.sessionManagement((session) -> {session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);}); // changing the sessionpolicy from stateful to complete stateless . i have commented this as the frontend program is not requesting csrf token each time and the frontend application is remembering the csrf token

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
                User user1 = new User("user1","TEMP USER","user1@sample.com",passwordEncoder.encode("user20"));
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
                User admin = new User("admin","ADMINSTRATOR","admin@sample.com",passwordEncoder.encode("admin22"));
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

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
