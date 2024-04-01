package com.example.projets2m.security.jwt;
import com.example.projets2m.Enum.Estatut;
import com.example.projets2m.model.RefreshToken;
import com.example.projets2m.model.User;
import com.example.projets2m.repositories.RefreshTokenRepository;
import com.example.projets2m.repositories.UserRepository;
import com.example.projets2m.security.TokenBlackListService;
import com.example.projets2m.security.UserDetailsImpl;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import io.jsonwebtoken.security.Keys;


@Component
public class JwtUtils {

    @Autowired
    private TokenBlackListService tokenBlacklistService;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UserRepository userRepository;
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${Amine.app.jwtSecret}")
    private String jwtSecret;

    @Value("${Amine.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    @Value("2592000000")
    private Long refreshTokenExpirationMs;


    public RefreshToken generateRefreshToken(String username) {
        try {
            SecureRandom random = new SecureRandom();
            byte[] randomBytes = new byte[16];
            random.nextBytes(randomBytes);
            String randomString = Base64.getEncoder().encodeToString(randomBytes);
            String data = username + randomString + "BK637104";
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes());

            RefreshToken refreshToken = new RefreshToken();

            refreshToken.setToken(Base64.getEncoder().encodeToString(hash));
            refreshToken.setDateGeneration(LocalDateTime.now());
            refreshToken.setStatut(Estatut.Actif);
            refreshToken.setUsername(username);
            // Set the expiration date based on your requirements
            refreshToken.setDateExpiration(new Date((new Date()).getTime() + refreshTokenExpirationMs)); // Example: expiration in 30 days
            // Set the user
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
            refreshToken.setUser(user);

            return refreshTokenRepository.save(refreshToken);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error generating refresh token: {}", e.getMessage());
            return null;
        }
    }


    public boolean validateRefreshToken(String refreshToken) {
        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByToken(refreshToken);
        if (optionalRefreshToken.isPresent()) {
            RefreshToken token = optionalRefreshToken.get();
            // Vérifie si le token a expiré
            if (token.getDateExpiration().after(new Date())) {
                return true; // Le token est valide
            }
        }
        return false; // Le token est invalide ou introuvable
    }



    public String generateJwtToken(Authentication authentication) {

        UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject((userPrincipal.getUsername()))
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }



    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
    public boolean validateJwtToken(String authToken) {
        try {
            if (tokenBlacklistService.isTokenInvalid(authToken)) {
                logger.error("JWT token is blacklisted");
                return false;
            }

            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }





    public String getUserNameFromJwtToken(String token) {
        if (validateJwtToken(token)) {
            return Jwts.parserBuilder().setSigningKey(key()).build()
                    .parseClaimsJws(token).getBody().getSubject();
        }
        return null;
    }





}
