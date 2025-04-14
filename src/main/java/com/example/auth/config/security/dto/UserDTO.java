package com.example.auth.config.security.dto;


import lombok.Getter;
import lombok.Setter;
import org.keycloak.representations.idm.CredentialRepresentation;

import java.util.List;

@Getter
@Setter
public class UserDTO {
    private String username;
    private String email;
    private String password;
    private List<String> roles;
    private List<CredentialRepresentation> credentials;

    // Getters and setters
}