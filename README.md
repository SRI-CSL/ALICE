# Automated-instrumentation of Legacy Insecure Cryptographic Executables (ALICE)

Implementation flaws in cryptographic libraries, design flaws in underlying cryptographic primitives, and weaknesses in protocols using both, can all lead to exploitable vulnerabilities in software. Manually fixing such issues is challenging and resource consuming, especially when maintaining legacy software that contains broken or outdated cryptography, and for which source code may not be available. While there is existing work on identifying cryptographic primitives (often in the context of malware analysis), none of this prior work has focused on replacing such primitives with stronger (or more secure ones) after they have been identified. This project explores feasibility of designing and implementing a toolchain for Automated-instrumentation of Legacy Insecure Cryptographic Executables (ALICE). The key features of ALICE are: (i) automatically detecting and extracting implementations of weak or broken cryptographic primitives from binaries without requiring source code or debugging symbols, (ii) identifying the context and scope in which such primitives are used, and performing program analysis to determine the effects of replacing such implementations with more secure ones, and (iii) replacing implementations of weak primitives with those of stronger or more secure ones. We demonstrate practical feasibility of our approach on cryptographic hash functions with several popular cryptographic libraries and real-world programs of various levels of complexity. Our experimental results show that ALICE can locate and replace insecure hash functions, even in large binaries (we tested ones of size up to 1.5MB), while preserving existing functionality of the original binaries, and while incurring minimal execution-time overhead in the rewritten binaries.


A paper covering ALICE paper can be found [here](https://arxiv.org/abs/2004.09713).

For more details about the code, how ot run it, and examples, see python/README.md



