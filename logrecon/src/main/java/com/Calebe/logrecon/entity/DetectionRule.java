package com.Calebe.logrecon.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AccessLevel;

//getter is a easier way
@Getter
@NoArgsConstructor(access=AccessLevel.PROTECTED)
@Entity
@Table(name="detection_rule")
public class DetectionRule{
    
    //create the id to this class
    @Id
    @GeneratedValue
    private Long id;

    //get ID to Log Source;
    @ManyToOne
    @JoinColumn(name="mitre_tactic_id")
    private MitreTactic tactic;

    private String name;
    private String conditionConfig;
    private String severity;

    //protect constructor for database;
    //but lombok makes it easier
    //protected DetectionRule(){}

    public DetectionRule(MitreTactic tactic, String name, String conditionConfig, String severity){
        this.tactic = tactic;
        this.name = name;
        this.conditionConfig = conditionConfig;
        this.severity = severity;
    }

    @Override
    public String toString(){
        return String.format("DetectionRule[id=%d, mitretactic=%d, name=%s, conditionConfig=%s, severity=%s]", id, tactic.getId(), name, conditionConfig, severity);
    }

}