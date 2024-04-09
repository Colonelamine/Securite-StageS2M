package com.example.projets2m.web;

import com.example.projets2m.Crypt.EncryptDecryptService;
import com.example.projets2m.Enum.ERole;
import com.example.projets2m.Enum.Estatut;
import com.example.projets2m.model.Role;
import com.example.projets2m.model.User;

import lombok.extern.java.Log;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.security.*;
import javax.crypto.Cipher;

import com.example.projets2m.payload.request.LoginRequest;
import com.example.projets2m.payload.request.SignupRequest;
import com.example.projets2m.payload.response.JwtResponse;
import com.example.projets2m.payload.response.MessageResponse;
import com.example.projets2m.repositories.RefreshTokenRepository;
import com.example.projets2m.repositories.RoleRepository;
import com.example.projets2m.repositories.UserRepository;
import com.example.projets2m.security.CustomUserDetailsService;
import com.example.projets2m.security.TokenBlackListService;
import com.example.projets2m.security.UserDetailsImpl;
import com.example.projets2m.security.jwt.AuthTokenFilter;
import com.example.projets2m.security.jwt.JwtUtils;
import com.example.projets2m.security.jwt.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.logging.Level;
import java.util.stream.Collectors;


@Transactional
@RestController
@RequestMapping("/auth")
@AllArgsConstructor
@Log
public class AuthController {


    @Autowired
    AuthenticationManager authenticationManager;
    UserRepository userRepository;
    RefreshTokenService refreshTokenService;
    RoleRepository roleRepository;
    PasswordEncoder encoder;
    RefreshTokenRepository refreshTokenRepository;
    CustomUserDetailsService customUserDetailsService;
    JwtUtils jwtUtils;
    AuthTokenFilter authTokenFilter;
    TokenBlackListService tokenBlackListService;

    @Autowired
    EncryptDecryptService encryptDecryptService;

    // Générer une paire de clés RSA (une seule fois au démarrage de l'application)
   /* @Autowired
    private KeyPair keyPair;
    @Autowired
    // Récupérer la clé privée pour le déchiffrement RSA
    private PrivateKey privateKey;

    public void DecryptionController() {
        // Récupérer la clé privée de la paire de clés RSA générée précédemment
        this.privateKey = keyPair.getPrivate();
    }

    public void EncryptionController() throws NoSuchAlgorithmException {
        // Initialisation du générateur de clés RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Taille de la clé RSA (2048 bits est recommandé pour la sécurité)
        this.keyPair = keyPairGenerator.generateKeyPair(); // Générer la paire de clés RSA
    }

    @PostMapping("/encrypt")
    public String encryptData(@RequestBody String data) throws Exception {
        // Récupérer la clé publique pour le chiffrement RSA
        PublicKey publicKey = keyPair.getPublic();

        // Initialiser le chiffrement RSA avec la clé publique
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        // Chiffrer les données
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());

        // Retourner les données chiffrées en tant que base64
        return java.util.Base64.getEncoder().encodeToString(encryptedBytes);
    }



    @PostMapping("/decrypt")
    public String decryptData(@RequestBody String encryptedData) throws Exception {
        try {
            // Décoder la chaîne Base64 en tableau de bytes
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

            // Initialiser le déchiffrement RSA avec la clé privée
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Déchiffrer les données
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            // Convertir les bytes déchiffrés en chaîne JSON
            String decryptedJson = new String(decryptedBytes);

            // Retourner la chaîne JSON déchiffrée
            return decryptedJson;
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting data", e);
        }
    }
*/

    @GetMapping("/createKeys")
    public void createPrivatePublickey() {
        encryptDecryptService.createKeys();
    }

    @PostMapping("/test")
    public String encryptMessage(HttpServletRequest httpServletRequest) {
        String body = null;
        try {

            StringBuilder stringBuilder = new StringBuilder();
            BufferedReader bufferedReader = null;
            try {
                bufferedReader = httpServletRequest.getReader();
                char[] charBuffer = new char[128];
                int bytesRead;
                while ((bytesRead = bufferedReader.read(charBuffer)) != -1) {
                    stringBuilder.append(charBuffer, 0, bytesRead);
                }
            } finally {
                if (bufferedReader != null) {
                    bufferedReader.close();
                }
            }


            body = stringBuilder.toString();
            log.info("Body>>" + body + "<<");

        } catch (Throwable throwable) {
            log.severe("throwable" + throwable.getMessage());
            log.log(Level.ALL, "Error", throwable);
        }

        String plainString = "ddd";
        return encryptDecryptService.encryptMessage(plainString);
    }


    @PostMapping("/encrypt")
    public String encryptMessage(@RequestBody LoginRequest loginRequest) {
        return encryptDecryptService.encryptMessage(loginRequest.getPassword());
    }

    @PostMapping("/decrypt")
    public String decryptMessage(@RequestBody LoginRequest loginRequest) {
        return encryptDecryptService.decryptMessage(loginRequest.getPassword());
    }


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);
        String refreshToken = String.valueOf(jwtUtils.generateRefreshToken(loginRequest.getUsername()));


        if (jwt != null && refreshToken != null) {

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());


            return ResponseEntity.ok(new JwtResponse(jwt,
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles, refreshToken));

        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Invalid credentials"));
        }
    }


    @GetMapping("/newAccesToken")
    public ResponseEntity<?> validateToken(@RequestParam("token") String token) {
        boolean isValidRefreshToken = jwtUtils.validateRefreshToken(token);

        if (isValidRefreshToken) {
            // Extraire le nom d'utilisateur du token de rafraîchissement
            String username = refreshTokenService.getUsernameFromRefreshToken(token);

            if (username != null) {
                // Créer une nouvelle authentication pour cet utilisateur
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // Générer un nouveau token d'accès en utilisant l'objet Authentication
                String newAccessToken = jwtUtils.generateJwtToken(authentication);

                // Renvoyer la réponse avec le nouveau token d'accès
                return ResponseEntity.ok("new AccesToken :" + newAccessToken);
            } else {
                // Si le nom d'utilisateur n'est pas trouvé, renvoyer une réponse d'erreur
                return ResponseEntity.badRequest().body("Invalid refresh token");
            }
        } else {
            // Si le token de rafraîchissement n'est pas valide, renvoyer une réponse d'erreur
            return ResponseEntity.badRequest().body("Invalid refresh token");
        }
    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ADMIN)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "user":
                        Role modRole = roleRepository.findByName(ERole.USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(modRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request) {
        String token = authTokenFilter.parseJwt(request);

        if (token != null) {
            tokenBlackListService.invalidateToken(token);
            refreshTokenRepository.updateStatusByToken(token, Estatut.Inactif);
            return ResponseEntity.ok(new MessageResponse("User logged out successfully!"));
        } else {
            return ResponseEntity.badRequest().body(new MessageResponse("Invalid token"));
        }
    }


}

