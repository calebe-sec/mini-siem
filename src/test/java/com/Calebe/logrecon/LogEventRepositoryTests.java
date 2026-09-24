package com.Calebe.logrecon;

import com.Calebe.logrecon.entity.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.boot.jpa.test.autoconfigure.TestEntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import repository
import com.Calebe.logrecon.repository.LogEventRepository;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class LogEventRepositoryTests {

    private static final Logger log = LoggerFactory.getLogger(LogEventRepositoryTests.class);

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private LogEventRepository repository;

    @Test
    void shouldSaveEventAssociatedWithASource() {
        LogSource source = entityManager.persistAndFlush(
            new LogSource("SSH auth", "vm-01", "SSH_AUTH", "syslog")
        );

        LocalDateTime logOfTimestamp = LocalDateTime.of(2026, 9, 18, 13, 45, 0);

        LogEvent event = repository.save(
            new LogEvent(source, logOfTimestamp, "10.0.0.5", "LOGIN_FAILED", "root",
                "Sep 18 13:45:00 vm-01 sshd[1234]: Failed password for root from 10.0.0.5", "HIGH")
        );

        log.info("Saved: {}", event);

        assertThat(event.getId()).isNotNull();
        assertThat(event.getSource().getId()).isEqualTo(source.getId());
        assertThat(event.getTimestamp()).isEqualTo(logOfTimestamp);
        assertThat(event.getEventType()).isEqualTo("LOGIN_FAILED");
        assertThat(event.getSeverity()).isEqualTo("HIGH");
    }
}