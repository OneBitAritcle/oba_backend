package oba.backend.server.security;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Collections;

@Component
@RequiredArgsConstructor
public class GoogleVerifier {

    @Value("${GOOGLE_CLIENT_ID}")
    private String googleClientId;

    private static final NetHttpTransport transport = new NetHttpTransport();
    private static final GsonFactory jsonFactory = new GsonFactory();

    public GoogleIdToken.Payload verify(String idTokenString) {
        try {
            if (googleClientId == null || googleClientId.isBlank()) {
                throw new IllegalStateException("GOOGLE_CLIENT_ID is missing. Check your .env or application.yml");
            }

            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken == null) {
                throw new RuntimeException("Invalid Google ID Token");
            }

            return idToken.getPayload();

        } catch (Exception e) {
            throw new RuntimeException("Google token verification failed", e);
        }
    }
}
