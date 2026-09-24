package com.Calebe.logrecon.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AccessLevel;

//getter is a easier way
@Getter
@NoArgsConstructor(access=AccessLevel.PROTECTED)
@Entity
@Table(name="alert")
public class Alert{

    //create the id to this class
    @Id
    @GeneratedValue
    private Long id;

    //get ID to Log Source;
    @ManyToOne
    @JoinColumn(name="rule_id")
    private DetectionRule rule;

    private LocalDateTime createdAt;
    
    private String status;
    private String description;

    //protect constructor for database;
    //but lombok makes it easier
    // protected Alert(){}

    public Alert(DetectionRule rule, String status, String description){
        this.rule = rule;
        this.status = status;
        this.description = description;
        this.createdAt = LocalDateTime.now();
    }

    @Override
    public String toString(){
        return String.format("Alert[id=%d, ruleId=%d, createdAt=%tF, status=%s, description=%s", 
        id, rule.getId(), createdAt, status, description);
    }

}