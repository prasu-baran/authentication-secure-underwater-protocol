#  Underwater Communication Security Simulation

This project implements a **secure multi-hop underwater communication protocol** with both simulation and formal verification.

---

#  Project Files

##  `uwc_simulation.py`
- Simulates a **multi-layer underwater network** (UWS → SUB → BUOY → SAT → BS).
- Implements **ECC-based authentication and encrypted communication** using ECDH.
- Supports **dynamic routing with fallback nodes** (e.g., B1 → B2, SAT1 → SAT2).
- Measures performance metrics like **delay, energy consumption, and communication cost**.

---

##  `uwc_protocol.spdl`
- Models the protocol using the **Scyther formal verification tool**.
- Verifies security properties such as **authentication (Alive, Niagree)** and **secrecy of nonces**.

---

#  Protocol Overview

- Establishes **secure communication across multiple hops** in underwater environments.  
- Uses **nonce-based challenge-response** to prevent replay attacks.  
- Ensures **confidentiality and integrity** through cryptographic mechanisms.  
- Supports **fault tolerance via backup nodes and dynamic path selection**.  

---

#  Results & Visualization

###  Network Topology
<img width="400" height="400" alt="Screenshot 2026-03-23 092156" src="https://github.com/user-attachments/assets/a94da032-a115-41dc-9a62-ad7935644e8f" />

*Shows the hierarchical multi-hop structure with fallback paths between nodes.*

###  Scyther Verification Results
<img width="400" height="400" alt="Screenshot 2026-03-22 214429" src="https://github.com/user-attachments/assets/944fa3fb-8750-4c25-bce8-8425ac95019f" />

*Displays formal verification of security claims, including authentication and secrecy properties.*

###  Delay vs Number of Nodes
<img width="400" height="400" alt="Screenshot 2026-03-23 092221" src="https://github.com/user-attachments/assets/c940ad8f-8f31-45a1-9e98-924b3ecfc155" />

*Illustrates how communication delay varies with increasing network size.*

###  Energy Consumption vs Nodes
<img width="400" height="400" alt="Screenshot 2026-03-23 092241" src="https://github.com/user-attachments/assets/4fdbbb46-eeca-4336-a5b7-d7417edda019" />

*Shows the growth of energy usage as the number of nodes increases.*

###  Communication Cost vs Nodes
<img width="400" height="400" alt="Screenshot 2026-03-23 092302" src="https://github.com/user-attachments/assets/f7d9e581-ac46-47f8-b5fa-52d6bef7d747" />

*Represents the increase in communication overhead with network scaling.*
