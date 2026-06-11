# Collusion-Resistant zkTLS co-SNARK

This repo contains the DVRF, threshold signature, and **co-SNARK** framework for:
*Provably Secure and Collusion-Resistant TLS Attestation Protocols for Decentralized Applications*.

Unlike the earlier DVRF-then-TSS prototype, this version measures the **end-to-end**
pipeline, adding the collaborative zk-SNARK (co-SNARK) handshake of the DECO-based
`dx-DCTLS` instantiation. The co-SNARK runs the full distributed SHA-256 TLS-PRF
(~1.9M R1CS constraints) under 2-party MPC, so the handshake (HSP) is now a
real, bandwidth-bound stage rather than an estimated upper bound.

The benchmark runs the full attestation for `t`-out-of-`n` nodes —
(5, 3), (9, 5), (13, 7), (19, 10), (29, 15), (39, 20), (59, 30), (79, 40), (99, 50) —
across LAN and two simulated WAN profiles, reporting per-stage time and network cost.

Pipeline per attestation: **DKG > DDH-DVRF > HSP (co-SNARK) > PGP > FROST TSS**.

## Running

```
./run_wan_tables.sh
```

This builds the co-SNARK prover and runs the end-to-end benchmark, producing the
three tables below (LAN, WAN1, WAN2). Compute is measured once and the network
overlay is applied analytically per profile, so the full sweep finishes in ~3 minutes.

WAN1 Configuration:
- One-way latency: 40ms ± 5ms
- RTT: 80ms
- Bandwidth: 50 Mbps
- Packet loss: 0.1%

WAN2 Configuration:
- One-way latency: 75ms ± 15ms
- RTT: 150ms
- Bandwidth: 20 Mbps
- Packet loss: 0.2%

## Columns

- **DKG / DVRF / HSP / PGP / TSS** — per-stage time (ms)
- **Total** — full pipeline time (ms)
- **noDKG** — Total - DKG (steady-state cost once the quorum key exists)
- **Net** — total communication volume (kb)
- **noDKG-Net** — Net - DKG volume (kb)

HSP communication is derived from the co-SNARK circuit size (~1.9M constraints x
one field element ~ 60 MB of MPC traffic), so HSP is bandwidth-bound: LAN << WAN1 < WAN2.

## Results

```
== LAN (RTT=0ms, one-way=0±0ms, 0Mbps, 0.0% loss) ==
Config         DKG    DVRF       HSP       PGP      TSS     Total      noDKG        Net   noDKG-Net
              (ms)    (ms)      (ms)      (ms)     (ms)      (ms)       (ms)       (kb)        (kb)
------------------------------------------------------------------------------------------------
3-of-5          10       0     11222      7324        1     18557      18547   59388.66    59377.35
5-of-9          51       0     11222      7324        2     18599      18548   59428.97    59378.84
7-of-13        143       0     11222      7324        4     18693      18550   59509.36    59380.32
10-of-19       423       0     11222      7324        8     18977      18554   59732.56    59382.55
15-of-29      1438       0     11222      7324       17     20001      18563   60482.93    59386.26
20-of-39      3407       0     11222      7324       30     21983      18576   61876.37    59389.97
30-of-59     11518       0     11222      7324       64     30128      18610   67377.60    59397.39
40-of-79     27182       0     11222      7324      111     45839      18657   77806.57    59404.81
50-of-99     53030       0     11222      7324      175     71751      18721   94733.58    59412.23

== WAN1 (RTT=80ms, one-way=40±5ms, 50Mbps, 0.1% loss) ==
Config         DKG    DVRF       HSP       PGP      TSS     Total      noDKG        Net   noDKG-Net
              (ms)    (ms)      (ms)      (ms)     (ms)      (ms)       (ms)       (kb)        (kb)
------------------------------------------------------------------------------------------------
3-of-5          92     241     21190      7364      162     29049      28957   59388.66    59377.35
5-of-9         139     401     21190      7364      163     29257      29118   59428.97    59378.84
7-of-13        244     561     21190      7364      166     29525      29281   59509.36    59380.32
10-of-19       561     802     21190      7364      171     30088      29527   59732.56    59382.55
15-of-29      1698    1203     21190      7364      181     31636      29938   60482.93    59386.26
20-of-39      3895    1604     21190      7364      195     34248      30353   61876.37    59389.97
30-of-59     12906    2405     21190      7364      232     44097      31191   67377.60    59397.39
40-of-79     30277    3207     21190      7364      281     62319      32042   77806.57    59404.81
50-of-99     58897    4009     21190      7364      348     91808      32911   94733.58    59412.23

== WAN2 (RTT=150ms, one-way=75±15ms, 20Mbps, 0.2% loss) ==
Config         DKG    DVRF       HSP       PGP      TSS     Total      noDKG        Net   noDKG-Net
              (ms)    (ms)      (ms)      (ms)     (ms)      (ms)       (ms)       (kb)        (kb)
------------------------------------------------------------------------------------------------
3-of-5         165     452     35992      7399      304     44312      44147   59388.66    59377.35
5-of-9         222     753     35992      7399      306     44672      44450   59428.97    59378.84
7-of-13        346    1055     35992      7399      310     45102      44756   59509.36    59380.32
10-of-19       717    1507     35992      7399      316     45931      45214   59732.56    59382.55
15-of-29      2038    2260     35992      7399      330     48019      45981   60482.93    59386.26
20-of-39      4576    3013     35992      7399      347     51327      46751   61876.37    59389.97
30-of-59     14937    4520     35992      7399      389     63237      48300   67377.60    59397.39
40-of-79     34870    6026     35992      7399      444     84731      49861   77806.57    59404.81
50-of-99     67648    7533     35992      7399      516    119088      51440   94733.58    59412.23
```

Warning!: This code is a research prototype. Do not use it in production.
