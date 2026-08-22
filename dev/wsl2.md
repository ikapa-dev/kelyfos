# Alternate Linux layer: Windows 11 + WSL2

The primary dev path is macOS + Lima (`dev/lima.yaml`, decision D9). WSL2 is an
equal-citizen alternate; so is any Linux/KVM box, which needs none of this.

## Enable nested virtualization

WSL2 does not expose `/dev/kvm` by default. Add to `%UserProfile%\.wslconfig`:

```ini
[wsl2]
nestedVirtualization=true
```

Then, from an elevated PowerShell:

```powershell
wsl --update
wsl --shutdown
```

Restart the distribution and confirm inside it:

```sh
ls -l /dev/kvm
```

If the node is missing, `wsl --update` is the usual fix — the feature requires a
recent WSL kernel, and Store-distributed WSL updates independently of Windows.

## Grant access to /dev/kvm

Same as the Lima path: the node is `root:kvm 0660` and the tarball-installed
Firecracker runs as your user. Either add yourself to the `kvm` group, or install
the same udev rule KelyfOS uses:

```sh
echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm"' \
  | sudo tee /etc/udev/rules.d/99-kelyfos-kvm.rules
sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
```

## Then

```sh
bash dev/install-firecracker.sh
make
```

`kelyfos doctor` (P3-11) detects the host flavor and prints the fix for whichever
of these is wrong.
