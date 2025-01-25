package com.notes.thinknotesbackend.config.security.securityfilter;

import com.notes.thinknotesbackend.config.security.customuserdetails.UserDetailsServiceImpl;
import com.notes.thinknotesbackend.config.security.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthTokenFilter extends OncePerRequestFilter {

	@Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());
        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}


// authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

//authentication.setDetails(...):
//:-
//The Authentication object in Spring Security represents the current user's authentication state.
//The setDetails() method sets additional information (details) about the authentication request, such as IP address, session ID, or other request metadata.
//These details are typically used for logging, auditing, or custom security checks

//new WebAuthenticationDetailsSource():
//:-
//The WebAuthenticationDetailsSource is a Spring Security class that provides an implementation for extracting web-specific details from an HTTP request.
//It collects information like:
//Remote IP address: The client's IP address making the request.
//Session ID: The session ID associated with the current request.

//.buildDetails(request):
//:-
//This method extracts details from the HttpServletRequest object and creates a WebAuthenticationDetails instance.
//The WebAuthenticationDetails object contains metadata about the authentication request (like IP address and session ID).

//The setDetails() line enriches the Authentication object with additional request-based details that can later be used by:
//1. Security Events Logging:
//      Track the IP address or session ID for auditing or debugging purposes.
//2. Custom Security Implementations:
//      Apply conditional security logic based on request details (e.g., blocking a specific IP address).
//3. Authentication Success Handlers:
//      Provide detailed logging or response customization after successful authentication.