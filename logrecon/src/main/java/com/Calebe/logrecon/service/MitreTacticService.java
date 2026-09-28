package com.Calebe.logrecon.service;

import com.Calebe.logrecon.dto.MitreTacticRequest;
import com.Calebe.logrecon.entity.MitreTactic;
import com.Calebe.logrecon.repository.MitreTacticRepository;
import org.springframework.stereotype.Service;

@Service
public class MitreTacticService {

    private final MitreTacticRepository repository;

    public MitreTacticService(MitreTacticRepository repository) {
        this.repository = repository;
    }

    public MitreTactic register(MitreTacticRequest request) {
        MitreTactic tactic = new MitreTactic(request.tacticId(), request.name(), request.description());
        return repository.save(tactic);
    }
}