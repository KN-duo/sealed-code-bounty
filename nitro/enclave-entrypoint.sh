#!/bin/bash
set -euo pipefail

# The pinned Nitro bootstrap mounts cgroup v1 controllers. The judge requires
# these kernel-enforced limits; never fall back to execution without them.
for control in memory/memory.limit_in_bytes cpu/cpu.cfs_quota_us pids/pids.max; do
  if [[ ! -w "/sys/fs/cgroup/$control" ]]; then
    echo 'required sandbox cgroup controller unavailable' >&2
    exit 1
  fi
done

# The exploit runtime is embedded in the measured EIF. Never pull images over
# a network from inside the enclave.
/usr/bin/podman --storage-driver vfs load --input /app/scb-exploit-runtime.tar >/dev/null

/app/scb-runner &
runner_pid=$!
/usr/bin/python3 -u /app/nitro/enclave_proxy.py &
proxy_pid=$!

stop_children() {
  kill "$proxy_pid" "$runner_pid" 2>/dev/null || true
  wait "$proxy_pid" "$runner_pid" 2>/dev/null || true
}
trap stop_children TERM INT

set +e
wait -n "$runner_pid" "$proxy_pid"
status=$?
set -e
stop_children
exit "$status"
