# Two NixOS VMs with real OpenZFS: `sender` pushes with real syncoid through real sshd into
# the gate on `host`. Proves the grammar matches syncoid 2.3.0 and that the delegation,
# the zone, the quota, and the encryption policy behave as the README promises.
{
  pkgs,
  hostModule,
  senderModule,
}:
let
  hostPublicKey = pkgs.lib.strings.trim (builtins.readFile ./integration/host_key.pub);
  clientPublicKey = pkgs.lib.strings.trim (builtins.readFile ./integration/client_key.pub);
  zfsNode = {
    boot.supportedFilesystems = [ "zfs" ];
    networking.hostId = "deadbeef";
    virtualisation.emptyDiskImages = [ 1024 ];
    virtualisation.memorySize = 2048;
  };
in
pkgs.testers.runNixOSTest {
  name = "zfs-tenant-integration";

  nodes.host =
    { nodes, ... }:
    {
      imports = [
        hostModule
        zfsNode
      ];
      services.openssh = {
        enable = true;
        hostKeys = [
          {
            path = "/etc/ssh/ssh_host_ed25519_key";
            type = "ed25519";
          }
        ];
      };
      environment.etc."ssh/ssh_host_ed25519_key" = {
        source = ./integration/host_key;
        mode = "0600";
      };
      services.zfs-tenant = {
        enable = true;
        tenants.joe = {
          dataset = "tank/friends/joe";
          quota = "256M";
          authorizedKeys = [ clientPublicKey ];
          # /etc/hosts maps node names to both families; ssh may pick either.
          allowedFrom = [
            nodes.sender.networking.primaryIPAddress
            nodes.sender.networking.primaryIPv6Address
          ];
        };
      };
    };

  nodes.sender =
    { ... }:
    {
      imports = [
        senderModule
        zfsNode
      ];
      environment.etc."zfs-tenant-sender/id_ed25519" = {
        source = ./integration/client_key;
        mode = "0400";
        user = "zfs-tenant-sender";
      };
      services.zfs-tenant-sender = {
        enable = true;
        targets.host = {
          host = "host";
          user = "zfs-tenant-joe";
          sshKey = "/etc/zfs-tenant-sender/id_ed25519";
          knownHosts = "host ${hostPublicKey}";
          datasets."src/offsite" = "tank/friends/joe/offsite";
        };
      };
    };

  testScript = ''
    import shlex

    gate = (
        "timeout 120 ssh -T -i /etc/zfs-tenant-sender/id_ed25519 -o IdentitiesOnly=yes "
        "-o BatchMode=yes -o UserKnownHostsFile=/etc/zfs-tenant-sender/host.known_hosts "
        "-o StrictHostKeyChecking=yes zfs-tenant-joe@host"
    )

    def via_gate(command):
        # For pipelines that feed a stream into the gate.
        return f"{gate} {shlex.quote(command)}"

    def ask_gate(command):
        # Without a pipe, ssh would read the test driver's console as its stdin.
        return f"{via_gate(command)} </dev/null"

    def snapshots(dataset):
        return host.succeed(f"zfs list -H -o name -t snapshot -r {dataset}")

    pid_file = "/run/zfs-tenant/joe/holder.pid"

    def as_tenant_in_zone(command):
        # What the gate's own processes see: the tenant uid inside its user namespace.
        inner = f"nsenter --user --preserve-credentials --target $(cat {pid_file}) -- {command}"
        return f"su zfs-tenant-joe -s /bin/sh -c {shlex.quote(inner)}"

    def push():
        status, _ = sender.execute("systemctl start zfs-tenant-push-host.service")
        if status != 0:
            print(sender.execute("journalctl -u zfs-tenant-push-host.service --no-pager -n 100")[1])
            print(host.execute("journalctl -t zfs-tenant --no-pager -n 60")[1])
            raise AssertionError("syncoid push failed; journals above")

    start_all()
    host.wait_for_unit("sshd.service")
    sender.wait_for_unit("multi-user.target")

    with subtest("pools, datasets, and delegation exist"):
        host.succeed("zpool create -f -O mountpoint=none tank /dev/vdb")
        host.succeed("zfs create -o mountpoint=/srv/host tank/host")
        host.succeed("echo host-secret > /srv/host/secret")
        host.succeed("systemctl restart zfs-tenant-setup-joe.service")
        # Setup failed at boot (no pool yet), so its zone never started.
        host.succeed("systemctl restart zfs-tenant-zone-joe.service")
        host.wait_until_succeeds(f"test -s {pid_file}")
        sender.succeed("zpool create -f -O mountpoint=/src src /dev/vdb")
        sender.succeed("printf correcthorsebatterystaple > /root/pp")
        sender.succeed(
            "zfs create -o encryption=on -o keyformat=passphrase "
            "-o keylocation=file:///root/pp src/offsite"
        )
        sender.succeed("zfs create src/offsite/photos && zfs create src/offsite/docs")
        sender.succeed("head -c 2M /dev/urandom > /src/offsite/photos/a.jpg")
        sender.succeed("head -c 4M /dev/urandom > /src/offsite/docs/b.pdf")
        sender.succeed("zfs snapshot -r src/offsite@autosnap_1")
        sender.succeed("systemctl restart zfs-tenant-sender-delegate.service")

    with subtest("setup locks down the tenant root and is idempotent"):
        props = host.succeed(
            "zfs get -H -o property,value quota,mountpoint,readonly,volmode,zoned,filesystem_limit "
            "tank/friends/joe"
        )
        for expected in ["quota\t256M", "mountpoint\tnone", "readonly\ton", "volmode\tnone", "zoned\ton"]:
            assert expected in props, props
        # zfs allow prints the rights both sets share as "Local+Descendent".
        allow = " ".join(host.succeed("zfs allow tank/friends/joe").split())
        assert "Local+Descendent permissions: user zfs-tenant-joe create,mount,receive" in allow, allow
        assert "Descendent permissions: user zfs-tenant-joe destroy,send" in allow, allow
        host.succeed("systemctl restart zfs-tenant-setup-joe.service")
        # Requires= restarts the zone with setup, giving it a fresh namespace.
        host.wait_until_succeeds(f"test -s {pid_file}")

    with subtest("syncoid pushes raw encrypted datasets through the gate"):
        push()
        assert "tank/friends/joe/offsite/photos@autosnap_1" in snapshots("tank/friends/joe")
        keystatus = host.succeed("zfs get -H -o value keystatus tank/friends/joe/offsite/photos")
        assert keystatus.strip() == "unavailable", keystatus
        sender.succeed("zfs snapshot -r src/offsite@autosnap_2")
        push()
        assert "tank/friends/joe/offsite/docs@autosnap_2" in snapshots("tank/friends/joe")

    with subtest("the host never mounts tenant data"):
        host.succeed("zfs mount -a")
        assert "friends" not in host.succeed("mount")

    with subtest("the tenant sees only its own subtree"):
        listing = sender.succeed(ask_gate("zfs list -H -o name -r"))
        assert "tank/friends/joe/offsite" in listing, listing
        assert "tank/host" not in listing, listing
        for command in [
            "zfs list -r tank",
            "zfs get -H name tank/host",
            "sudo zfs get -H name tank/friends/joe",
            "cat /etc/passwd",
            "reboot",
            "zfs destroy tank/friends/joe",
            "zfs destroy -r tank/host",
        ]:
            out = sender.fail(ask_gate(command) + " 2>&1")
            assert "command not allowed" in out, (command, out)
        out = sender.fail(f"{gate} 2>&1 </dev/null")
        assert "interactive sessions are not allowed" in out, out
        host.succeed("test -e /srv/host/secret")

    with subtest("inside its zone the kernel hides the rest of the pool"):
        listing = host.succeed(as_tenant_in_zone("zfs list -H -o name -t all"))
        assert "tank/friends/joe/offsite" in listing, listing
        assert "tank/host" not in listing, listing
        out = host.fail(as_tenant_in_zone("zfs get -H -o value used tank/host") + " 2>&1")
        assert "dataset does not exist" in out, out

    with subtest("outside its zone the tenant user cannot write its zoned datasets"):
        # zoned=on: delegated rights only apply from inside the zone, so a tenant process
        # that escaped the namespace could not change anything either.
        out = host.fail("su zfs-tenant-joe -s /bin/sh -c 'zfs create tank/friends/joe/outside' 2>&1")
        assert "permission denied" in out, out

    with subtest("the gate fails closed while the zone is down and recovers on restart"):
        host.succeed("systemctl stop zfs-tenant-zone-joe.service")
        out = sender.fail(ask_gate("zfs list") + " 2>&1")
        assert "the tenant namespace is not running" in out, out
        host.succeed("systemctl start zfs-tenant-zone-joe.service")
        host.wait_until_succeeds(f"test -s {pid_file}")
        assert "tank/friends/joe/offsite" in sender.succeed(ask_gate("zfs list -H -o name -r"))

    with subtest("the kernel denies the tenant user outside its subtree"):
        # Even with a shell and no gate, delegation stops the tenant user at its root.
        for command in [
            "zfs snapshot tank/friends/joe@x",
            "zfs set quota=none tank/friends/joe",
            "zfs allow -u zfs-tenant-joe quota tank/friends/joe",
            "zfs destroy tank/host",
        ]:
            out = host.fail(f"su zfs-tenant-joe -s /bin/sh -c {shlex.quote(command)} 2>&1")
            assert "permission denied" in out, (command, out)

    with subtest("plaintext streams are refused and removed"):
        sender.succeed("zfs create -o encryption=off src/plain && echo hi > /src/plain/x")
        sender.succeed("zfs snapshot src/plain@s1")
        out = sender.fail(
            "zfs send src/plain@s1 | " + via_gate("zfs receive tank/friends/joe/plain") + " 2>&1"
        )
        assert "refused unencrypted dataset tank/friends/joe/plain" in out, out
        host.fail("zfs list tank/friends/joe/plain")

    with subtest("an interrupted receive resumes"):
        sender.fail(
            "zfs send -w src/offsite/docs@autosnap_2 | head -c 1000000 | "
            + via_gate("zfs receive -s tank/friends/joe/resume")
        )
        row = sender.succeed(ask_gate("zfs get -H receive_resume_token tank/friends/joe/resume"))
        token = row.split("\t")[2]
        assert token not in ("", "-"), row
        sender.succeed(f"zfs send -t {token} | " + via_gate("zfs receive -s tank/friends/joe/resume"))
        encryption = host.succeed("zfs get -H -o value encryption tank/friends/joe/resume")
        assert encryption.strip() != "off", encryption

    with subtest("syncoid pruning mirrors the sender's retention"):
        sender.succeed("zfs snapshot -r src/offsite@autosnap_3")
        push()
        sender.succeed("zfs destroy -r src/offsite@autosnap_2")
        # syncoid only prunes after sending something new, as happens with every sanoid run.
        sender.succeed("zfs snapshot -r src/offsite@autosnap_4")
        push()
        remaining = snapshots("tank/friends/joe/offsite/photos")
        assert "autosnap_2" not in remaining and "autosnap_4" in remaining, remaining

    with subtest("the tenant creates and removes its own datasets"):
        sender.succeed(ask_gate("zfs create -p tank/friends/joe/scratch/a"))
        host.succeed("zfs list tank/friends/joe/scratch/a")
        sender.succeed(ask_gate("zfs destroy -r tank/friends/joe/scratch"))
        host.fail("zfs list tank/friends/joe/scratch")

    with subtest("a restore through the gate decrypts on the sender"):
        sender.succeed(
            ask_gate("zfs send -w tank/friends/joe/offsite/docs@autosnap_3")
            + " | zfs receive -u src/restored"
        )
        sender.succeed("zfs load-key -L file:///root/pp src/restored")
        # Setting a mountpoint mounts the now-unlocked dataset; mount -a covers either order.
        sender.succeed("zfs set mountpoint=/restored src/restored && zfs mount -a")
        sender.succeed("cmp /restored/b.pdf /src/offsite/docs/b.pdf")

    with subtest("an interrupted restore resumes through the gate"):
        sender.fail(
            ask_gate("zfs send -w tank/friends/joe/offsite/docs@autosnap_3")
            + " | head -c 1000000 | zfs receive -s -u src/restored-docs"
        )
        token = sender.succeed(
            "zfs get -H -o value receive_resume_token src/restored-docs"
        ).strip()
        sender.succeed(ask_gate(f"zfs send -t {token}") + " | zfs receive -s -u src/restored-docs")
        sender.fail(ask_gate("zfs send -t 1-0-0-0"))

    with subtest("the quota caps what the tenant can store"):
        sender.succeed("zfs create src/offsite/big")
        sender.succeed("head -c 300M /dev/urandom > /src/offsite/big/blob")
        sender.succeed("zfs snapshot src/offsite/big@autosnap_5")
        out = sender.fail(
            "zfs send -w src/offsite/big@autosnap_5 | "
            + via_gate("zfs receive tank/friends/joe/offsite/big")
            + " 2>&1"
        )
        assert "quota exceeded" in out, out
  '';
}
