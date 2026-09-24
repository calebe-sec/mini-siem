package com.Calebe.logrecon.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.AccessLevel;

//getter is a easier way
@Getter
@NoArgsConstructor(access=AccessLevel.PROTECTED)
@Entity
@Table(name="mitre_tactic")
public class MitreTactic{
    
    //create the id to this class
    @Id
    @GeneratedValue
    private Long id;
    
    @Column(name = "tactic_id", unique = true, nullable = false)
    private String tacticId;
    private String name;
    private String description;

    //protect constructor for database;
    //but lombok makes it easier
    // protected MitreTactic(){}

    public MitreTactic(String tacticId, String name, String description){
        this.tacticId = tacticId;
        this.name = name;
        this.description = description;
    }
    
    @Override
    public String toString() {
        return String.format("MitreTactic[id=%d, tacticId=%s, name=%s, description=%s]",
        id, tacticId, name, description);
    }
}