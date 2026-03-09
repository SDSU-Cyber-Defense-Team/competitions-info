# CCDC Ansible Safeguard

## Install

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install -y pipx openssh-client
pipx ensurepath
source ~/.bashrc
pipx install ansible-core
pipx inject ansible-core passlib
ansible-galaxy collection install -r requirements.yml
```

**RHEL/CentOS/Fedora:**
```bash
sudo dnf install -y pipx openssh
pipx ensurepath
source ~/.bashrc
pipx install ansible-core
pipx inject ansible-core passlib
ansible-galaxy collection install -r requirements.yml
```

---

## Setup

Fill in `group_vars/all/vault.yml` with real values:
```yaml
initial_password: ""      # root password on target machines
admin_password: ""        # password for the created admin account
admin_ssh_passphrase: ""  # passphrase for the SSH keypair
```

Then encrypt it:
```bash
ansible-vault encrypt group_vars/all/vault.yml
```

Edit `inventory.yml` to set target IPs.
Edit `group_vars/all/vars.yml` to change `admin_user` if needed.

---

## Workflows

### Pre-bootstrap connectivity test
```bash
ansible all -m ping --ask-vault-pass
```

### Bootstrap (competition - root access)
```bash
ansible-playbook playbooks/safeguard_init.yml --ask-vault-pass
ssh-add ssh_keys/failsafe/id_ed25519
```

### Bootstrap (testing - non-root sudo user)
```bash
ansible-playbook playbooks/safeguard_init.yml --ask-vault-pass -e "ansible_user=<initial_user>"
ssh-add ssh_keys/failsafe/id_ed25519
```
Note: `ansible_become_password` defaults to `admin_password`. If the sudo user's password differs, override it too: `-e "ansible_become_password=<their_password>"`.

### Key rotation
```bash
ansible-playbook playbooks/ssh_rotate.yml --ask-vault-pass
ssh-add ssh_keys/failsafe/id_ed25519
```

---

## Structure

```
├── ansible.cfg
├── inventory.yml
├── requirements.yml
├── group_vars/
│   └── all/
│       ├── vars.yml     # non-sensitive config
│       └── vault.yml    # ansible-vault encrypted
├── playbooks/
│   ├── safeguard_init.yml
│   └── ssh_rotate.yml
└── tasks/
    ├── ssh/
    │   ├── generate_keypair.yml
    │   ├── deploy_pubkey.yml
    │   └── rotate_key.yml
    └── user/
        ├── create_user.yml
        └── configure_sudo.yml
```

## Notes

- `ssh_keys/` is gitignored.
- Active key is always at `ssh_keys/<admin_user>/id_ed25519`.
- Old keys archive to `ssh_keys/<admin_user>/archive/`.
- After rotation reload the key with `ssh-add`.
