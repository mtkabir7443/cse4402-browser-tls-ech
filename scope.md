# Approved scope and delivery boundary

Solo PKI/Web project 3: a browser-driven TLS/cipher-suite/ECH comparison website. Requirements derive from the course project handout and Professor Herzberg's replies provided by Mohammed Kabir.

The approved expansion includes several additional browsers, specifically older Chrome and Firefox, a result webpage, persistent result logging with client IP, and an aggregate comparison. A local demo is accepted; external availability is preferred but optional. The final deliverable is a written report introducing and motivating the measurements, presenting results and drawing conclusions. Complete coverage and good documentation are the stated grading criteria; no grade has been awarded here.

The implemented experiment uses seven builds, twelve controlled configurations, and three fresh-state repetitions: 252 actual measurements. These counts were the project's chosen operational scope, not separately prescribed instructor counts. TLS version, suite and ECH configurations are specified in the design and report. HTTP/3, broad certificate/revocation tests and a separate DNSSEC suite are outside this approved scope.

The [five-page design](documents/CSE4402_TLS_ECH_Design_Nov22.pdf) is due November 22 at 11:59 p.m. EST. It specifies the goals, software components, and experimental methods. The written report and [GitHub code link](https://github.com/mtkabir7443/cse4402-browser-tls-ech) are due December 18. HuskyCT submission remains pending.

Private research records and correspondence remain outside this source package. The included sanitized dataset covers all 252 cells; its consistency verifier is distinct from the full raw-evidence audit retained locally.
