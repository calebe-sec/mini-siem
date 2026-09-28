package com.Calebe.logrecon.repository;

import com.Calebe.logrecon.entity.MitreTactic;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MitreTacticRepository extends JpaRepository<MitreTactic, Long> {
    Optional<MitreTactic> findByTacticId(String tacticId);
}