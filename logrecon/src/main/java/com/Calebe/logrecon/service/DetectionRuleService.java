package com.Calebe.logrecon.service;

import com.Calebe.logrecon.dto.DetectionRuleRequest;
import com.Calebe.logrecon.entity.DetectionRule;
import com.Calebe.logrecon.entity.MitreTactic;
import com.Calebe.logrecon.repository.DetectionRuleRepository;
import com.Calebe.logrecon.repository.MitreTacticRepository;
import org.springframework.stereotype.Service;

@Service
public class DetectionRuleService {

    private final DetectionRuleRepository ruleRepository;
    private final MitreTacticRepository tacticRepository;

    public DetectionRuleService(DetectionRuleRepository ruleRepository, MitreTacticRepository tacticRepository) {
        this.ruleRepository = ruleRepository;
        this.tacticRepository = tacticRepository;
    }

    public DetectionRule register(DetectionRuleRequest request) {
        MitreTactic tactic = tacticRepository.findByTacticId(request.tacticId())
            .orElseThrow(() -> new IllegalArgumentException("Unknown tactic: " + request.tacticId()));

        DetectionRule rule = new DetectionRule(tactic, request.name(), request.conditionConfig(), request.severity());
        return ruleRepository.save(rule);
    }
}