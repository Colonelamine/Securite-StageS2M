package com.example.projets2m.repositories;


import com.example.projets2m.model.TokenBlackListEntity;
import org.springframework.data.jpa.repository.JpaRepository;


public interface TokenBlackListEntityRepository extends JpaRepository<TokenBlackListEntity, Integer> {
    boolean existsByToken(String token);
}
