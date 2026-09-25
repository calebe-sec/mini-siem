package com.Calebe.logrecon.service;

import com.Calebe.logrecon.dto.AlertRequest;
import com.Calebe.logrecon.entity.Alert;
import com.Calebe.logrecon.entity.AlertEvent;
import com.Calebe.logrecon.entity.DetectionRule;
import com.Calebe.logrecon.entity.LogEvent;
import com.Calebe.logrecon.repository.AlertEventRepository;
import com.Calebe.logrecon.repository.AlertRepository;
import com.Calebe.logrecon.repository.DetectionRuleRepository;
import com.Calebe.logrecon.repository.LogEventRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AlertService {

    private final AlertRepository alertRepository;
    private final DetectionRuleRepository ruleRepository;
    private final LogEventRepository eventRepository;
    private final AlertEventRepository alertEventRepository;

    public AlertService(AlertRepository alertRepository, DetectionRuleRepository ruleRepository,
                         LogEventRepository eventRepository, AlertEventRepository alertEventRepository) {
        this.alertRepository = alertRepository;
        this.ruleRepository = ruleRepository;
        this.eventRepository = eventRepository;
        this.alertEventRepository = alertEventRepository;
    }

    public Alert register(AlertRequest request) {
        DetectionRule rule = ruleRepository.findByName(request.rule())
            .orElseThrow(() -> new IllegalArgumentException("Unknown rule: " + request.rule()));

        Alert alert = alertRepository.save(new Alert(rule, request.status(), request.description()));

        List<LogEvent> events = eventRepository.findAllById(request.logEventIds());
        if (events.size() != request.logEventIds().size()) {
            throw new IllegalArgumentException("One or more log events not found");
        }

        for (LogEvent event : events) {
            alertEventRepository.save(new AlertEvent(alert, event));
        }

        return alert;
    }
}