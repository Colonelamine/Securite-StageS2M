package com.example.projets2m.repositories;

import com.example.projets2m.Enum.Estatut;
import com.example.projets2m.model.RefreshToken;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;


import java.util.Optional;
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken,Long> {
    Optional<RefreshToken> findByToken(String refreshToken);

    @Modifying
    @Transactional
    @Query("UPDATE RefreshToken t SET t.statut = :status WHERE t.token = :token")
    int updateStatusByToken(@Param("token") String token, @Param("status") Estatut status);



}
