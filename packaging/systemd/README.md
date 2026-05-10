# Linux packaging

The unit at `edr-agent.service` is the source of truth for the agent's
systemd integration. It ships in both the `.deb` and `.rpm` produced by
M7.3 (`make agent-linux-deb` / `make agent-linux-rpm`) and is also
usable for ad-hoc lab installs as described below.

## Package install (preferred)

```bash
make agent-linux-deb            # writes target/debian/edr-agent_*.deb
sudo apt-get install -y target/debian/edr-agent_0.1.0-1_amd64.deb

# or for RHEL / Rocky / Alma 9:
make agent-linux-rpm            # writes target/generate-rpm/edr-agent-*.rpm
sudo dnf install -y target/generate-rpm/edr-agent-0.1.0-1.x86_64.rpm

# Service is installed but DISABLED. Edit /etc/edr/agent.env to set
# EDR_MANAGER_ENDPOINT and EDR_ENROLLMENT_TOKEN, then:
sudo systemctl enable --now edr-agent
```

## Manual install (lab use, no package)

```bash
sudo install -m 0755 target/release/edr-agent /usr/bin/edr-agent
sudo install -m 0644 packaging/systemd/edr-agent.service \
    /etc/systemd/system/edr-agent.service
sudo install -d -m 0755 /etc/edr
sudo install -m 0640 packaging/systemd/agent.env.example /etc/edr/agent.env
sudo $EDITOR /etc/edr/agent.env       # set endpoint + enrollment token
sudo systemctl daemon-reload
sudo systemctl enable --now edr-agent
sudo systemctl status edr-agent
```

## Verifying self-protection

```bash
# Should fail. Agent stays alive.
sudo kill -9 $(pgrep edr-agent)
sudo gdb -p $(pgrep edr-agent)
sudo head -c 16 /proc/$(pgrep edr-agent)/mem
sudo rm /sys/fs/bpf/edr/links/handle_task_kill
sudo rm /var/lib/edr/blocklist.json
sudo bpftool link detach id $(sudo bpftool -j link show \
  | python3 -c 'import json,sys;print(next(l["id"] for l in json.load(sys.stdin) if "lsm" in str(l)))')

# Should succeed (init delivers the signal).
sudo systemctl stop edr-agent

# Stats — counters should have ticked up under self_blocked=k:N/t:N/b:N/u:N.
sudo journalctl -u edr-agent --no-pager -n 5
```

## Recovery

If the agent has crashed and pinned objects remain in `/sys/fs/bpf/edr/`,
the next start runs an automatic takeover (claim + unpin). To remove
all pinned state manually (e.g. when uninstalling for good):

```bash
sudo systemctl stop edr-agent
sudo /usr/bin/edr-agent --unpin
```
