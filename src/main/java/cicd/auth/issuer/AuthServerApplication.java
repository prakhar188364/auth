package main.java.cicd.auth.issuer;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class AuthServerApplication {

    public static void main(String[] args) {
       new SpringApplicationBuilder().sources(AuthServerApplication.class).run(args);
    }

}