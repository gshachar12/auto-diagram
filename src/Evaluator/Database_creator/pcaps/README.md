# PCAP Files and Network Attack Documentation

This directory contains packet capture files (pcaps) and related documentation for various DDoS attacks, used as input data for the auto-diagram system.

## Directory Structure

### NRDelegationAttack/
Contains documentation and analysis for the NRDelegation attack:

#### Core Documentation
- `NRDelegationAttack.pdf` - Main research paper
- `NRDelegationAttack-appendix.pdf` - Technical appendix for running the attack's simulation
- `NRDelegationAttack.md` - Markdown version of the main paper with structured formatting
- `NRDelegationAttack.txt` - Text version of the main paper

#### Simulation Data
- **Simulator_Figure1/** - Experiment data
  - `NRDelegationAttack_figure1.pcap` - Packet capture from attack simulation as described for figure 1 in the paper
  - `Figure 1.png` - Visual diagram of the attack flow from the paper
  - `Figure1_NRDelegationAttack.md` - Detailed explanation of the NRDelegation attack for figure 1

### NSCacheFlush/
Contains comprehensive materials for the NSCacheFlush DNS cache poisoning attack:

#### Core Documentation
- `NSCacheFlush - ֿA Flushing Attack on the DNS Cache.pdf` - Main research paper
- `NSCacheFlush-appendix.pdf` - Technical appendix for running the attack's simulation
- `NSCacheFlush.md` - Markdown version of the main paper with structured formatting
- `NSCacheFlush.txt` - Text version of the main paper

#### Simulation Data
- **Simulator_E1/** - Experiment 1 data
  - `CacheFlushSimulator_E1_test_appendix.pcap` - Packet capture from simulation E1
  - `Figure 1.png` - Visual diagram of the attack flow from the paper
  - `Figure1_NSCacheFlush.md` - Detailed explanation of the NS records attack variant

- **Simulator_E2/** - Experiment 2 data
  - `CacheFlushSimulator_E2_test_appendix.pcap` - Packet capture from simulation E2
  - `Figure 2.png` - Visual diagram of CNAME-based attack flow from the paper
  - `Figure2_CNAMECacheFlush.md` - Detailed explanation of the CNAME attack variant



## Attack Types Documented

### NSCacheFlush Attack
A DNS cache poisoning attack that exploits DNS resolvers by:
1. Sending queries for malicious domains
2. Receiving referral responses with excessive NS records (up to 1500 names)
3. Causing cache pollution and eviction of legitimate records
4. Resulting in cache thrashing and potential service degradation

**Variants:**
- **NS Records Attack (E1)**: Uses excessive NS record responses
- **CNAME Attack (E2)**: Leverages CNAME records for cache manipulation

### NRDelegation Attack
A sophisticated DNS attack targeting delegation mechanisms (documentation only).

## Usage in Auto-Diagram

These pcap files and documentation serve as:
- **Context files** for generating accurate network diagrams
- **Reference materials** for validating diagram accuracy
- **Examples** for demonstrating the auto-diagram system capabilities

## File Formats

- **`.pcap`** - Wireshark packet capture files containing network traffic
- **`.pdf`** - Research papers and technical documentation
- **`.md`** - Markdown files with structured attack explanations
- **`.png`** - Visual diagrams and flowcharts
- **`.txt`** - Plain text summaries and notes


*Note: All packet captures and documentation are for educational and research purposes only.*