package com.zkteco.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.zkteco.security.auth.AuthenticationService;
import com.zkteco.security.auth.RegisterRequest;
import com.zkteco.security.user.Role;

@SpringBootApplication
@ComponentScan("com.zkteco.security")
@EnableJpaRepositories("com.zkteco.security.token")
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}
	
	@Bean
	public CommandLineRunner commandLineRunner(AuthenticationService service) {
		return args -> {
			var admin=RegisterRequest.builder()
					.firstName("Admin")
					.lastName("Admin")
					.email("admin@mail.com")
					.password("password")
					.role(Role.ADMIN)
					.build();
		System.out.println("Admin token: "+service.register(admin).getToken());	
		
		
		var manager=RegisterRequest.builder()
				.firstName("Admin")
				.lastName("Admin")
				.email("manager@mail.com")
				.password("password")
				.role(Role.MANAGER)
				.build();
	    System.out.println("Manager token: "+service.register(manager).getToken());
		};
	}

}
