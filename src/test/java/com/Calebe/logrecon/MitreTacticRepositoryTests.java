package com.Calebe.logrecon;

import com.Calebe.logrecon.entity.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import repository
import com.Calebe.logrecon.repository.MitreTacticRepository;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class MitreTacticRepositoryTests {

    private static final Logger log = LoggerFactory.getLogger(MitreTacticRepositoryTests.class);

    @Autowired
    private MitreTacticRepository repository;

    @Test
    void shouldSaveATactic() {
        MitreTactic tactic = repository.save(
            new MitreTactic("TA0006", "Credential Access", "Attempts to obtain credentials")
        );

        log.info("Saved: {}", tactic);

        assertThat(tactic.getId()).isNotNull();
        assertThat(tactic.getTacticId()).isEqualTo("TA0006");
        assertThat(tactic.getName()).isEqualTo("Credential Access");
    }
}