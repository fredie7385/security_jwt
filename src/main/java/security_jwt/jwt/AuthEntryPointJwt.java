package security_jwt.jwt;

// Importing necessary classes for JSON serialization, servlet handling, logging, HTTP media types, security exceptions, and component declaration
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

// Declaring this class as a Spring component so that it can be autowired where needed
@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {
    // Creating a logger instance for logging purposes
    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);
    /**
     * Handles unauthorized access attempts by customizing the HTTP response sent back to the client.
     * This method is invoked whenever an unauthenticated user tries to access a secured endpoint.
     *
     * @param request The original request made by the client
     * @param response The response object to write the error message to
     * @param authException The exception thrown due to failed authentication
     * @throws IOException If an I/O error occurs during the response writing process
     * @throws ServletException If a servlet-related error occurs
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        // Logging the unauthorized attempt along with the exception message
        logger.error("Unauthorized error: {}", authException.getMessage());

        // Setting the content type of the response to JSON
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // Setting the HTTP status code to indicate unauthorized access
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // Creating a map to hold the response body
        final Map<String, Object> body = new HashMap<>();
        // Adding fields to the response body
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);
        body.put("error", "Unauthorized");
        body.put("message", authException.getMessage());
        body.put("path", request.getServletPath());

        // Using Jackson's ObjectMapper to serialize the response body and write it to the response output stream
        final ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }
}
