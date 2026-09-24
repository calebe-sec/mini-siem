package com.Calebe.logrecon;

import com.Calebe.logrecon.entity.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import repository
import com.Calebe.logrecon.repository.AlertRepository;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class AlertRepositoryTests {

    private static final Logger log = LoggerFactory.getLogger(AlertRepositoryTests.class);

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private AlertRepository repository;

    @Test
    void needSearchAndSaveAlert() {
        // Alert depends on DetectionRule, which depends on MitreTactic —
        // the entire chain must be persisted before creating the Alert
        MitreTactic tactic = entityManager.persistAndFlush(
            new MitreTactic("TA0006", "Credential Access", "Attempts to obtain credentials")
        );

        DetectionRule rule = entityManager.persistAndFlush(
            new DetectionRule(tactic, "Repeated failed SSH logins", "{}", "HIGH")
        );

        Alert alert = repository.save(
            new Alert(rule, "OPEN", "5 failed login attempts from the same IP within 2 minutes")
        );

        log.info("Saved: {}", alert);

        assertThat(alert.getId()).isNotNull();
        assertThat(alert.getCreatedAt()).isNotNull();
        assertThat(alert.getStatus()).isEqualTo("OPEN");
        assertThat(alert.getRule().getId()).isEqualTo(rule.getId());
    }
}