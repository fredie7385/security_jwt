package security_jwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Greetings {
    @GetMapping("/")
    public String getName() {
        return "Hello";
    }
}
