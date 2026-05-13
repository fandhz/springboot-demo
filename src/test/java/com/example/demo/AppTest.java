package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootApplication
public class VulnerableApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }
}

// ==========================================
// 1. CONFIGURATION: CELAH SECURITY FILTER
// ==========================================
@Configuration
class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                // VULNERABLE: EndpointRequest.to() pada versi 3.2.1 gagal memvalidasi path secara ketat
                // Penyerang bisa memanipulasi request untuk membypass filter otentikasi ini
                .requestMatchers(EndpointRequest.to("health", "info")).permitAll() 
                .anyRequest().authenticated()
            );
        return http.build();
    }
}

// ==========================================
// 2. CONTROLLER: CELAH OPEN REDIRECT / SSRF
// ==========================================
@RestController
class VulnerableController {

    @GetMapping("/redirect")
    public String safeRedirect(@RequestParam String targetUrl) {
        // VULNERABLE: UriComponentsBuilder salah mengekstrak host jika ada karakter khusus seperti '[' atau '@'
        String host = UriComponentsBuilder.fromUriString(targetUrl)
                                          .build()
                                          .getHost();

        // Logika aplikasi mengira host ini AMAN karena memeriksa nilai "trusteddomain.com"
        if ("trusteddomain.com".equals(host)) {
            // Pada aplikasi nyata, baris ini memicu HTTP 302 Redirect
            return "Berhasil melewati validasi! Mengalihkan ke host: " + targetUrl; 
        }

        return "Akses Ditolak: Host tidak terpercaya!";
    }
}
