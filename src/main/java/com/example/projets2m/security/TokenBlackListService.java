package com.example.projets2m.security;
import com.example.projets2m.model.TokenBlackListEntity;
import com.example.projets2m.repositories.TokenBlackListEntityRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


@Service
public class TokenBlackListService {
    @Autowired
    private TokenBlackListEntityRepository tokenBlacklistRepository;

    @Transactional
    public void invalidateToken(String token) {
        System.out.println("Entering invalidateToken method"); // Add this line for debugging
        try {
            if (!tokenBlacklistRepository.existsByToken(token)) {
                tokenBlacklistRepository.save(new TokenBlackListEntity(token));
                System.out.println("Token added to blacklist: " + token);
            } else {
                System.out.println("Token already in blacklist: " + token);
            }
        } catch (Exception e) {
            System.out.println("Exception caught: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
        System.out.println("Exiting invalidateToken method");
    }

    public boolean isTokenInvalid(String token) {
        return tokenBlacklistRepository.existsByToken(token);
    }
}
