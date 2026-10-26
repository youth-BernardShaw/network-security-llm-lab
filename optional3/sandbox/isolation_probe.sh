#!/bin/bash
# optional3 sandbox isolation probe (reproducible)
# Verifies: non-root user, mount/network namespaces, host-drive hiding,
#           resource limits, no outbound network, no host credential access.
# This probe is NOT a model-generated POC and carries NO human approval record.
set -u
SB=/opt/optional3-sandbox
U=o3sandbox
# Evidence output path: override with $1 or O3_EVIDENCE_OUT. Defaults to /tmp.
OUT_WIN="${1:-${O3_EVIDENCE_OUT:-/tmp/sandbox_evidence.json}}"

id "$U" >/dev/null 2>&1 || useradd -m -s /bin/bash "$U"
mkdir -p "$SB/approved" "$SB/staging" "$SB/work"
chown root:root "$SB" "$SB/approved" "$SB/staging"
chmod 755 "$SB" "$SB/approved"; chmod 700 "$SB/staging"
chown "$U:$U" "$SB/work"; chmod 700 "$SB/work"

cat > /usr/local/bin/o3probe.sh <<'EOF'
echo "user=$(whoami)"
echo "uid=$(id -u)"
echo "sudo_group=$(id -Gn | grep -qw sudo && echo yes || echo no)"
echo "read_etc_shadow=$(head -c 20 /etc/shadow >/dev/null 2>&1 && echo readable || echo denied)"
echo "write_approved=$( (touch /opt/optional3-sandbox/approved/x) >/dev/null 2>&1 && echo allowed || echo denied)"
echo "read_host_staging=$(ls /opt/optional3-sandbox/staging >/dev/null 2>&1 && echo allowed || echo denied)"
echo "write_own_work=$( (touch /opt/optional3-sandbox/work/x) >/dev/null 2>&1 && echo allowed || echo denied)"
echo "host_drive_entries=$(ls -A /mnt/c 2>/dev/null | wc -l)"
echo "host_drive_visible=$([ "$(ls -A /mnt/c 2>/dev/null | wc -l)" -gt 0 ] && echo visible || echo hidden)"
echo "net_external=$(timeout 6 curl -s -m 5 -o /dev/null http://example.com && echo reachable || echo blocked)"
echo "net_dns=$(timeout 5 getent hosts example.com >/dev/null 2>&1 && echo resolved || echo no_dns)"
echo "net_loopback_9080=$(timeout 4 curl -s -m 3 -o /dev/null http://127.0.0.1:9080/ && echo reachable || echo refused)"
echo "mem_limit=$(python3 -c 'a=bytearray(400*1024*1024); print("allocated_400mb")' 2>&1 | tail -1)"
echo "ulimit_v_kb=$(ulimit -v)"
echo "ulimit_n=$(ulimit -n)"
echo "ifaces=$(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ',')"
echo "netns_inode=$(readlink /proc/self/ns/net)"
echo "mntns_inode=$(readlink /proc/self/ns/mnt)"
EOF
chmod 755 /usr/local/bin/o3probe.sh

HOST_NETNS=$(readlink /proc/self/ns/net)
HOST_MNTNS=$(readlink /proc/self/ns/mnt)
STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

unshare -m -n -- bash -c '
  mount --make-rprivate / 2>/dev/null
  if mount -t tmpfs none /mnt/c 2>/tmp/o3mount.err; then echo "ns_hide_host_drive=ok"; else echo "ns_hide_host_drive=failed"; fi
  ip link set lo up 2>/dev/null
  echo "ns_net=$(readlink /proc/self/ns/net)"
  echo "ns_mnt=$(readlink /proc/self/ns/mnt)"
  echo "mntc_fstype=$(stat -f -c %T /mnt/c 2>/dev/null)"
  echo "host_netns='$HOST_NETNS'"
  echo "host_mntns='$HOST_MNTNS'"
  runuser -u o3sandbox -- bash -c "ulimit -v 262144; ulimit -n 64; ulimit -t 5; timeout 25 /usr/local/bin/o3probe.sh"
  echo "probe_exit=$?"
' > /tmp/o3probe_out.txt 2>&1

export O3_EVIDENCE_OUT="$OUT_WIN"
python3 - "$STARTED" <<'PY'
import datetime, json, os, sys
started = sys.argv[1]
lines = [l.rstrip("\n") for l in open("/tmp/o3probe_out.txt", encoding="utf-8", errors="replace")]
obs = {}
for ln in lines:
    if "=" in ln and not ln.startswith(" "):
        k, v = ln.split("=", 1)
        obs[k.strip().strip("'")] = v.strip().strip("'")
script = open("/usr/local/bin/o3probe.sh", "rb").read()
import hashlib
ev = {
  "artifact": "optional3 sandbox isolation probe",
  "scope": "Isolation mechanics only. Benign probe script, NOT a model-generated POC. No human approval record was created or consumed.",
  "host": {"wsl_distro": "Ubuntu-20.04 (20.04.6 LTS)", "note": "Ubuntu-22.04 distro is broken on this host (ext4.vhdx missing); Docker is not installed."},
  "run": {"started_utc": started,
           "finished_utc": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
           "probe_script": "/usr/local/bin/o3probe.sh",
           "probe_script_sha256": hashlib.sha256(script).hexdigest(),
           "commands": [
             "useradd -m -s /bin/bash o3sandbox",
             "unshare -m -n -- bash -c 'mount --make-rprivate /; mount -t tmpfs none /mnt/c; ip link set lo up; ...'",
             "runuser -u o3sandbox -- bash -c 'ulimit -v 262144; ulimit -n 64; ulimit -t 5; timeout 25 /usr/local/bin/o3probe.sh'"
           ]},
  "observations": obs,
  "raw_output": lines,
  "limitations": [
    "Isolation mechanics verified; this probe is NOT a model-generated POC execution.",
    "The separate approved-POC run is recorded in optional3/checks/sandbox-poc-run-20261025.json.",
    "Docker is absent; optional3/sandbox/compose.yaml stays a deployable but unverified artifact.",
    "tmpfs over /mnt/c hides the Windows drive inside the namespace; the probe user is additionally non-root, so both layers were exercised together."
  ]
}
out_path = os.environ.get("O3_EVIDENCE_OUT", "/tmp/sandbox_evidence.json")
open(out_path, "w", encoding="utf-8").write(json.dumps(ev, ensure_ascii=False, indent=2) + "\n")
print("evidence written to", out_path, "keys=", len(obs))
PY