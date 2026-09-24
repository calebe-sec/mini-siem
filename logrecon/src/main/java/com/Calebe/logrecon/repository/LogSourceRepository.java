package com.Calebe.logrecon.repository;

import com.Calebe.logrecon.entity.LogSource;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface LogSourceRepository extends JpaRepository<LogSource, Long>{
    Optional<LogSource> findByName(String name);
}