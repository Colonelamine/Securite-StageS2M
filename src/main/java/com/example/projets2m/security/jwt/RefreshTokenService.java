package com.example.projets2m.security.jwt;

import com.example.projets2m.model.RefreshToken;
import com.example.projets2m.repositories.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RefreshTokenService {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    public String getUsernameFromRefreshToken(String refreshToken) {
        // Recherchez le token de rafraîchissement dans la base de données en fonction du token spécifié
        Optional<RefreshToken> optionalRefreshToken = refreshTokenRepository.findByToken(refreshToken);

        // Vérifiez si le token de rafraîchissement existe dans la base de données
        if (optionalRefreshToken.isPresent()) {
            // Si le token existe, récupérez l'entité RefreshToken
            RefreshToken refreshTokenEntity = optionalRefreshToken.get();
            // Retournez le nom d'utilisateur associé à ce token
            return refreshTokenEntity.getUsername();
        } else {
            // Si le token de rafraîchissement n'est pas trouvé dans la base de données, retournez null ou une valeur par défaut selon vos besoins
            return null;
        }
    }
}

