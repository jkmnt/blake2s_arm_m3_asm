# blake2s_arm_m3_asm
blake2s hash efficiently coded in arm cortex-m3 assembly

The code is believed to have a good space/speed balance. 
It's about the fastest one can get without inlining all the rounds.

The code size is about 1300 bytes.


The perfomance on STM-32F105 (36MHz, running from flash with two waitstates):

|size | time, ms |
|---|---|
|1024 | 1|
|2048 | 2|
|4096 | 4|
|8192 | 7|
| 16384 | 15|
