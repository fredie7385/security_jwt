package security_jwt.jwt;

// Importing necessary classes for servlet filtering, logging, dependency injection, security components, and exception handling
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

// Declaring this class as a Spring component so that it can be autowired where needed
@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    // Creating a logger instance for logging purposes
    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    // Autowiring the JwtUtils service for JWT operations
    @Autowired
    private JwtUtils jwtUtils;

    // Autowiring the UserDetailsService for loading user details
    @Autowired
    private UserDetailsService userDetailsService;

    /**
     * Filters incoming HTTP requests to check for a JWT token in the Authorization header.
     * If a valid token is found, it authenticates the user and sets the authentication in the SecurityContext.
     * Otherwise, it allows the request to proceed without authentication.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());
        try {
            // Extracting the JWT token from the request header
            String jwt = parseJwt(request);
            if (jwt!= null && jwtUtils.validateJwtToken(jwt)) {
                // Extracting the username from the JWT token
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                // Loading user details based on the extracted username
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Creating an authentication token with the loaded user details
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                // Setting the authentication in the SecurityContext
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }
        // Proceeding with the next filter in the chain
        filterChain.doFilter(request, response);
    }

    /**
     * Helper method to extract the JWT token from the Authorization header of the HTTP request.
     */
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}

