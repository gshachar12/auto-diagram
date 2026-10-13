# Figure 2 — CacheFlush Attack using CNAME records

*Figure 2: CacheFlush Attack using CNAME records example; An attacker requests the e1.attack.com domain and fills the benign cache with 17 RR sets from his authoritative name server.*

---

## Details

- Attack uses **CNAMECacheFlush** variant.  
- The attacker queries `e1.attack.com`.  
- The authoritative server replies with a **CNAME chain of 17 records** (maximum that BIND stores).  
- The resolver:  
  - Stores the first CNAME record in the benign cache.  
  - Continues to query the chain step by step, redundantly, until the vendor’s limit is reached (BIND = 17, Unbound = 9, Google = 15, Cloudflare = 20).  
- A total of **17 CNAME records** are stored in the benign cache.  
- Unlike the NS variant, this attack adds fewer entries per query but still consumes cache space and resolver processing time.  
