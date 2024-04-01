package com.example.projets2m.web;
import com.example.projets2m.Enum.ERole;
import com.example.projets2m.Enum.Estatut;
import com.example.projets2m.model.Role;
import com.example.projets2m.model.User;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Transactional
@RestController
@RequestMapping("/auth")
@AllArgsConstructor
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


    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);
        String refreshToken = String.valueOf(jwtUtils.generateRefreshToken(loginRequest.getUsername()));



        if (jwt != null  && refreshToken != null ) {
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



    /*@GetMapping("/validate-token")
    public ResponseEntity<?> validateToken(@RequestParam("token") String token) {
        boolean isValidRefreshToken = jwtUtils.validateRefreshToken(token);
            return ResponseEntity.ok(isValidRefreshToken);

        }*/



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
                return ResponseEntity.ok("new AccesToken :"+newAccessToken);
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

