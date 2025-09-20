# Figure 1 — Delegation Server Variant of NRDelegationAttack (Flow Overview)

*Figure 1: “Delegation server” variant of the NRDelegationAttack flow overview, focused on the resolver requests and responses.*

---

## Details

- The attacker queries `attack0.home.lan`.  
- Resolver contacts `home.lan`.  
- `home.lan` responds with a **Large Referral Response (LRR)** containing up to 1,500 NS names.  
- Resolver processes the LRR:
  - Performs **2n cache/ADB lookups** (heavy CPU/memory cost).  
  - Resolves `k` NS names at a time (`k=5` in BIND9).  
  - Sets the `No_Fetch` flag.  
- Each of the `k` names leads to a **delegation to a non-responsive server**.  
- Each delegation triggers a **restart event**, which clears the `No_Fetch` flag and loops back.  
- Loop continues until:
  - restart-limit = 100, or  
  - timeout.  
- Final outcome: resolver returns **FAIL** to client.  
