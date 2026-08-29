# Example target bundle

A company packages their vulnerable program like this — a Dockerfile plus its
source — and uploads it (small: source, not a built image). The enclave builds it
per bounty and runs submitted exploits against it.

Two rules the enclave depends on:
- serve the vulnerable service on a TCP port (declared in the bounty; 1337 here);
- keep the secret at **/flag**, root-owned, not world-readable. The enclave
  injects a fresh random flag there each run, so a PASS proves a real leak.

Zip the contents (not the folder) and that's the source bundle:
    cd enclave-exec/example-target && zip -qr ../example-target.zip .
