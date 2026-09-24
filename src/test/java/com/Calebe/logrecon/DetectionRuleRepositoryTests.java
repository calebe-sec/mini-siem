package com.Calebe.logrecon;

import com.Calebe.logrecon.entity.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import repository
import com.Calebe.logrecon.repository.DetectionRuleRepository;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class DetectionRuleRepositoryTests {

    private static final Logger log = LoggerFactory.getLogger(DetectionRuleRepositoryTests.class);

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private DetectionRuleRepository repository;

    @Test
    void mustSaveRuleAssociatedWithATactic() {
        MitreTactic tactic = entityManager.persistAndFlush(
            new MitreTactic("TA0006", "Credential Access", "Attempts to obtain credentials")
        );

        DetectionRule rule = repository.save(
            new DetectionRule(tactic, "Repeated failed SSH logins", "{}", "HIGH")
        );

        log.info("Saved: {}", rule);

        assertThat(rule.getId()).isNotNull();
        assertThat(rule.getName()).isEqualTo("Repeated failed SSH logins");
        assertThat(rule.getSeverity()).isEqualTo("HIGH");
        assertThat(rule.getTactic().getId()).isEqualTo(tactic.getId());
    }
}