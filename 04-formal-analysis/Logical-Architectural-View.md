flowchart TB
    U[User / External System] --> ORQ[GAT Orchestrator]
    ORQ --> A1[Agent A]
    ORQ --> A2[Agent B]
    subgraph "Agent (GAT Model)"
        DEC[Decision Layer]
        VAL[Validation Layer]
        POL[Policy Layer\n(ACP)]
        EXEC[Execution Layer]
        STATE[State Layer]
        OBS[Observability Layer]
    end
    A1 --> DEC
    DEC --> VAL --> POL --> EXEC
    EXEC --> STATE
    DEC & VAL & POL & EXEC --> OBS
    EXEC --> SYS[Corporate Systems]
    OBS --> LOG[ACP Audit Ledger]
