package com.Calebe.logrecon.repository;

import com.Calebe.logrecon.entity.DetectionRule;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface DetectionRuleRepository extends JpaRepository<DetectionRule, Long>{
    Optional<DetectionRule> findByName(String name);
}