# Lessons

- AWS's new Free Plan is controlled by service-control policies and is not the
  same as a conventional standalone AWS account. Check actual API access in the
  project's home region before recommending IAM Identity Center or a region.
- Enabling Organizations/Identity Center can upgrade a Free Plan and may affect
  promotional credits. Prefer short-lived `aws login` console credentials for
  this account; do not create long-lived access keys.
- A Nitro Enclave has no direct network or persistent storage. Do not assume a
  Docker-based verifier can be copied into the enclave unchanged; use a parent
  vsock proxy and an enclave-compatible process sandbox.
- Never create billable cloud resources during preparation. Produce and review
  the infrastructure plan, price, shutdown policy, and teardown command first.
- Keep the user's buyer and hunter workflow intact when adding hosting previews
  or reworking the TEE. Use a separate preview entry point; do not replace the
  main application routes with a teaser or disable the original CTF features.
