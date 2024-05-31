package security_jwt.jwt;

// Importing necessary classes for handling JWT tokens
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

// Declaring this class as a Spring component so that it can be autowired where needed
@Component
public class JwtUtils {

    // Creating a logger instance for logging purposes
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    // Injecting the JWT secret key from application properties
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    // Injecting the JWT expiration time from application properties
    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    /**
     * Extracts the JWT token from the Authorization header of the HTTP request.
     * Returns the token if found, otherwise returns null.
     */
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken!= null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // Remove Bearer prefix
        }
        return null;
    }

    /**
     * Generates a JWT token based on the provided user details.
     * The token includes the username as its subject and has an expiration time set according to the application properties.
     */
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs)) // Setting the token to expire after jwtExpirationMs milliseconds
                .signWith(key()) // Signing the token using the HMAC SHA key derived from the jwtSecret
                .compact(); // Compacting the token into its final string representation
    }

    /**
     * Parses and validates the JWT token, returning the username contained within the token's payload.
     * Throws exceptions if the token is malformed, expired, unsupported, or if the claims string is empty.
     */
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key()) // Verifying the token signature
                .build().parseSignedClaims(token) // Parsing the claims of the token
                .getPayload() // Getting the payload of the token
                .getSubject(); // Extracting the subject (username) from the payload
    }

    /**
     * Generates a SecretKey object from the base64 decoded jwtSecret.
     * This key is used for signing and verifying JWT tokens.
     */
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret)); // Decoding the jwtSecret and generating a key
    }

    /**
     * Validates the provided JWT token.
     * Returns true if the token is valid, false otherwise.
     * Logs errors for common JWT validation issues.
     */
    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate"); // Debugging print statement
            Jwts.parser()
                    .verifyWith((SecretKey) key()) // Verifying the token signature
                    .build()
                    .parseSignedClaims(authToken); // Parsing the claims of the token
            return true; // Token is valid
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage()); // Logging error for invalid token
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage()); // Logging error for expired token
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage()); // Logging error for unsupported token
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage()); // Logging error for empty claims string
        }
        return false; // Token is not valid
    }
}
