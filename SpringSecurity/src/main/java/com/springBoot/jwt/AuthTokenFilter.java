package com.springBoot.jwt;

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
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());
        try {
            System.out.println("------ Filter the Token ------");
            String jwt = parseJwt(request);

            System.out.println("Jwt Token : " + jwt);

            if (jwt != null && jwtUtils.validateJwtToken(jwt)) {

                System.out.println("----- TRUE CONDITION IN FILTER -----");

                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                System.out.println("username : " + username);

                UserDetails userDetails =
                        userDetailsService.loadUserByUsername(username);

                System.out.println("user Details : " + userDetails);

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(userDetails,
                                null,
                                userDetails.getAuthorities());

                System.out.println("Username pass auth token : " + auth);

                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                auth.setDetails(new WebAuthenticationDetailsSource()
                        .buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
            System.out.println("----- FALSE CONDITION IN FILTER -----");
        }
        catch (Exception e) {
            System.out.println("----- CATCH FILTER -----");
            logger.error("Cannot set user authentication: {}", e.getMessage());;
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        System.out.println("------ parseJwt -------");

        String jwt = jwtUtils.getJwtFromHeader(request);
        System.out.println("first jwt : " + jwt);
        logger.debug("AuthTokenFilter.java: {}", jwt);

        return jwt;
    }
}
