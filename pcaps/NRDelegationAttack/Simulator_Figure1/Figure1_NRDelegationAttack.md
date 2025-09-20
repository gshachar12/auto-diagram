
# Figure 1 — Delegation Server Variant of NRDelegationAttack (Flow Overview)

*Figure 1: “Delegation server” variant of the NRDelegationAttack flow overview, focused on the resolver requests and responses.*

---

## Details

- The attacker queries `xyz.referral.com`.  
- Resolver contacts `referral.com`.  
- `referral.com` responds with a **Large Referral Response (LRR)** containing up to 1,500 NS names.  
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

---

## Phases of the NRDelegationAttack

### Phase I — Large Referral Response (LRR) Received

1. Attacker’s client queries the victim resolver about `xyz.referral.com`.
2. Victim resolver queries `referral.com`.
3. `referral.com` responds with a **Large Referral Response (LRR)** containing many NS records.

### Phase II — Resolver Processes the LRR

1. The resolver performs **2n cache lookups** (for each NS name and corresponding A/AAAA).
2. Begins resolving up to `k` referral-limit NS names (e.g., `k=5` in BIND9).
3. Sets `No_Fetch` flag to avoid excessive NS processing.
4. Queries the first batch of referral-limit NS names.

### Phase III — Delegation Loop and Restart

1. Each of the `k` NS names leads to a delegation to an **authoritative server** that is **non-responsive**.
2. Resolver triggers a **restart event**, clears `No_Fetch`, and starts resolving the next `k` names.
3. This loop continues until either:
   - Restart limit (e.g., 100 in BIND9) is reached, or
   - A timeout occurs.
4. Eventually, the resolver returns a **FAIL** response to the client.
