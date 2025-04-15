package com.example.auth.user;

import com.example.auth.user.dto.UserDTO;
import com.example.auth.keycloak.KeycloakAdminService;
import com.example.auth.user.dto.request.LoginRequestDTO;
import com.example.auth.user.dto.response.LoginResponseDTO;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private KeycloakAdminService keycloakAdminService;

    @PostMapping("/create")
    public ResponseEntity<?> createUser(@RequestBody UserDTO userDTO) {
        UserRepresentation user = keycloakAdminService.createUser(userDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequestDTO loginRequest) {
            return keycloakAdminService.authenticate(loginRequest);
    }

    // Add other endpoints for login, update, etc.
}