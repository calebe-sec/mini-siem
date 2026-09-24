package com.Calebe.logrecon.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AccessLevel;

//getter is a easier way
@Getter
@NoArgsConstructor(access=AccessLevel.PROTECTED)
@Entity
@Table(name="alert_event")
public class AlertEvent{

    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    @JoinColumn(name = "alert_id")
    private Alert alert;

    @ManyToOne
    @JoinColumn(name="log_event_id")
    private LogEvent logEvent;

    //protect constructor for database;
    //but lombok makes it easier
    //protected AlertEvent(){}

    public AlertEvent(Alert alert, LogEvent logEvent){
        this.alert = alert;
        this.logEvent = logEvent;
    }

    @Override
    public String toString() {
        return String.format("AlertEvent[id=%d, alertId=%d, logEventId=%d]",
            id, alert.getId(), logEvent.getId());
    }

}