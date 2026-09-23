# Figure 1 — NS records type of CacheFlush Attack

*Figure 1: NS records type of CacheFlush Attack; An attacker requests e1.attack.com followed by e2.attack.com and gets referral responses with 1500 names from the authoritative name server. The resolver queries the first 20 names in each list and evicts from the benign cache the RR corresponding to the referral list and the 20 responses. This evicts usenix.org from the cache.*

---

## Details

- Attack uses **NSCacheFlush** variant.  
- The attacker queries malicious domains (e.g., `e1.attack.com`, `e2.attack.com`).  
- The malicious authoritative server replies with referral responses containing **1500 NS names**.  
- The resolver caches all 1500 names, even though it only resolves the first 5–20.  
- As a result, each malicious query inserts about **1520 records** into the benign cache.  
- Benign records (e.g., `usenix.org`) are evicted before reuse, leading to cache thrashing.  
- The attack is repeated across multiple domains until the cache is overwhelmed.  
