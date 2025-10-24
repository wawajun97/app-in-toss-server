package kr.heylocal.server.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.auth.FirebaseAuth;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.InputStream;

@Configuration
public class FirebaseConfig {
    @Bean
    public FirebaseApp firebaseApp() {
        ClassPathResource resource = new ClassPathResource("firebase-adminsdk.json");

        GoogleCredentials googleCredentials = null;
        try {
            InputStream resourceInputStream = resource.getInputStream();
            googleCredentials = GoogleCredentials.fromStream(resourceInputStream);
        } catch (Exception exception) {
            throw new RuntimeException("Invalid firebase-adminsdk.json");
        }

        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(googleCredentials)
                .build();

        return FirebaseApp.initializeApp(options);
    }

    @Bean
    public FirebaseAuth firebaseAuth(FirebaseApp firebaseApp) {
        return FirebaseAuth.getInstance(firebaseApp);
    }
}
