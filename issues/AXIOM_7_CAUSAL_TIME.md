# AXIOM 7: Causal Time Ordering in Corodite P2P System

## 1. Overview of Causal Time
Causal time is crucial in distributed systems like Corodite P2P. It establishes a framework for ordering events based on their causal relationships, which ensures that actions taken by different peers can be understood in a consistent manner. This axiom emphasizes the importance of maintaining causality to uphold the system's reliability and predictability.

## 2. Code References with Line Numbers
The core logic for managing timestamps in the Corodite P2P system can be found in `coroditep2p.rs`. Here are some key references:
- **Line 76**: Initialization of the timestamp structure.
- **Line 115-130**: Methods for updating timestamps based on incoming events.
- **Lines 150-175**: Logic for ordering events using the provided timestamps, ensuring that the causal order is preserved.
  
## 3. Timestamp Propagation Through Events
Timestamps are propagated through events within the system. When an event is generated, the current timestamp is included, allowing peers to understand the event's causal context. This propagation mechanism ensures that all peers maintain a consistent view of the causal history. 

## 4. Invariants and Ordering Guarantees
The system guarantees certain invariants regarding event ordering. All events must adhere to the following:
- If event A causally precedes event B, then A must be processed before B at all peers.
- Events without causal ties can be processed in any order, preserving system flexibility without breaking consistency.

## 5. Clock Synchronization Assumptions
The system operates under the assumption that all peers can achieve a level of clock synchronization. While complete synchronization is not feasible in distributed systems, causal ordering can still be maintained through logical timestamps. The reliance on logical rather than physical clocks ensures that events are ordered correctly across peers despite clock drift.

## 6. Recovery Admissibility Based on Timestamps
In the event of a failure, recovery protocols in the Corodite P2P system rely heavily on the timestamps associated with each event. Only events with timestamps that fall within an admissible range during recovery are considered for reprocessing to ensure that the causal relationships are preserved. This ensures that the system returns to a consistent state without violating causal ordering. 

---
This documentation serves to elucidate the mechanisms of causal time ordering within the Corodite P2P system, highlighting its significance in achieving deterministic behavior across peers.