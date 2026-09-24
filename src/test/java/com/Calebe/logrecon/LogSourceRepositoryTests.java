package com.Calebe.logrecon;

import com.Calebe.logrecon.entity.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

//import repository
import com.Calebe.logrecon.repository.LogSourceRepository;

//logger imports
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
class LogSourceRepositoryTests {

    private static final Logger log = LoggerFactory.getLogger(LogSourceRepositoryTests.class);

    @Autowired
    private LogSourceRepository repository;

    @Test
    void shouldSaveLogSource() {

        LogSource logSource = new LogSource("Web Server", "192.168.1.10", "Apache", "combined");

        LogSource save = repository.save(logSource);
        log.info("Saved: {}", save);

        assertNotNull(save.getId());
    }
}