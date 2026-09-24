package com.Calebe.logrecon;

import com.Calebe.logrecon.entity.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import repository
import com.Calebe.logrecon.repository.AlertEventRepository;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class AlertEventRepositoryTests {

    private static final Logger log = LoggerFactory.getLogger(AlertEventRepositoryTests.class);

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private AlertEventRepository repository;

    @Test
    void shouldAssociateAlertWithLogEvent() {
        LogSource source = entityManager.persistAndFlush(
            new LogSource("SSH auth", "vm-01", "SSH_AUTH", "syslog")
        );

        LogEvent event = entityManager.persistAndFlush(
            new LogEvent(source, LocalDateTime.now(), "10.0.0.5", "LOGIN_FAILED", "root", "raw log line", "HIGH")
        );

        MitreTactic tactic = entityManager.persistAndFlush(
            new MitreTactic("TA0006", "Credential Access", "Attempts to obtain credentials")
        );

        DetectionRule rule = entityManager.persistAndFlush(
            new DetectionRule(tactic, "Repeated failed SSH logins", "{}", "HIGH")
        );

        Alert alert = entityManager.persistAndFlush(
            new Alert(rule, "OPEN", "5 failed login attempts from the same IP within 2 minutes")
        );

        AlertEvent alertEvent = repository.save(new AlertEvent(alert, event));

        log.info("Saved: {}", alertEvent);

        assertThat(alertEvent.getId()).isNotNull();
        assertThat(alertEvent.getAlert().getId()).isEqualTo(alert.getId());
        assertThat(alertEvent.getLogEvent().getId()).isEqualTo(event.getId());
    }
}