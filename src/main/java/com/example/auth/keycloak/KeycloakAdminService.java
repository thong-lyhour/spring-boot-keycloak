package com.example.auth.keycloak;

import com.example.auth.user.dto.UserDTO;
import com.example.auth.user.dto.request.LoginRequestDTO;
import com.example.auth.user.dto.response.LoginResponseDTO;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
public class KeycloakAdminService {

    @Value("${keycloak.auth-server-url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;


    public Keycloak getKeycloakInstance() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
    }

    public UserRepresentation createUser(UserDTO userDTO) {
        Keycloak keycloak = getKeycloakInstance();
        UsersResource usersResource = keycloak.realm(realm).users();

        UserRepresentation user = new UserRepresentation();
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setEnabled(true);  // Uncommented this important line
        user.setEmailVerified(false);  // Add if you need email verification

        CredentialRepresentation credential = createPasswordCredential(userDTO.getPassword());
        user.setCredentials(Collections.singletonList(credential));

        try (Response response = usersResource.create(user)) {
            validateResponse(response);

            String userId = extractUserId(response);
            UserResource userResource = usersResource.get(userId);

            assignRoles(keycloak, userResource, userDTO.getRoles());

            return userResource.toRepresentation();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create user: " + e.getMessage(), e);
        }
    }

    private CredentialRepresentation createPasswordCredential(String password) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);
        return credential;
    }

    private void validateResponse(Response response) {
        if (response.getStatus() != Response.Status.CREATED.getStatusCode()) {
            String error = response.readEntity(String.class);
            throw new RuntimeException("Keycloak user creation failed. Status: " +
                    response.getStatus() + ", Error: " + error);
        }
    }

    private String extractUserId(Response response) {
        String location = response.getLocation().getPath();
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private void assignRoles(Keycloak keycloak, UserResource userResource, List<String> roles) {
        if (roles == null || roles.isEmpty()) return;

        List<RoleRepresentation> realmRoles = roles.stream()
                .map(roleName -> {
                    RoleRepresentation role = keycloak.realm(realm).roles().get(roleName).toRepresentation();
                    if (role == null) {
                        throw new IllegalArgumentException("Role not found: " + roleName);
                    }
                    return role;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        userResource.roles().realmLevel().add(realmRoles);
    }

    public ResponseEntity<?> authenticate(LoginRequestDTO loginRequest) {
        try {
            String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, realm);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("grant_type", "password");
            map.add("client_id", clientId);
            map.add("client_secret", clientSecret);
            map.add("username", loginRequest.getUsername());
            map.add("password", loginRequest.getPassword());

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

            return ResponseEntity.ok().body(new LoginResponseDTO((String) response.getBody().get("access_token")));
        } catch (HttpClientErrorException e) {
            return ResponseEntity.status(e.getStatusCode()).body(Map.of("error", "Invalid credentials", "message", e.getMessage()));
        }
    }
}