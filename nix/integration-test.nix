# Two NixOS VMs with real OpenZFS and sanoid: each pushes with nixpkgs' services.syncoid through
# the other's SSH gate. Proves the grammar matches syncoid 2.3.0 and that the delegation,
# the zone, the quota, and the encryption policy behave as the README promises.
{
  pkgs,
  hostModule,
}:
let
  hostPublicKey = pkgs.lib.strings.trim (builtins.readFile ./integration/host_key.pub);
  clientPublicKey = pkgs.lib.strings.trim (builtins.readFile ./integration/client_key.pub);
  snapshotPolicy = {
    recursive = true;
    autosnap = true;
    autoprune = true;
    hourly = 2;
    daily = 0;
    weekly = 0;
    monthly = 0;
    yearly = 0;
  };
  zfsNode = {
    boot.supportedFilesystems = [ "zfs" ];
    # The disposable virtio disks have stable paths but no /dev/disk/by-id entries.
    boot.zfs.devNodes = "/dev/disk/by-path";
    # Neither machine has the keys for its incoming backups.
    boot.zfs.requestEncryptionCredentials = false;
    # The retention test advances a guest clock; NTP must not reset it.
    services.timesyncd.enable = false;
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
      boot.zfs.extraPools = [ "tank" ];
      # The test creates the pool after first boot; subsequent boots must import it.
      systemd.services.zfs-import-tank.unitConfig.ConditionPathExists = "/var/lib/test-pool-ready";
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
      services.sanoid = {
        enable = true;
        datasets."tank/outgoing" = snapshotPolicy;
      };
      programs.ssh.knownHosts.sender.publicKey = hostPublicKey;
      services.syncoid = {
        enable = true;
        sshKey = "/var/lib/syncoid/id_ed25519";
        localSourceAllow = [
          "send"
          "hold"
        ];
        commonArgs = [
          "--no-sync-snap"
          "--compress=none"
          "--delete-target-snapshots"
          "--sshoption=StrictHostKeyChecking=yes"
        ];
        commands."tank/outgoing" = {
          target = "zfs-tenant-bas@sender:src/friends/bas/outgoing";
          recursive = true;
          sendOptions = "w";
        };
      };
    };

  nodes.sender =
    { nodes, ... }:
    {
      imports = [
        hostModule
        zfsNode
      ];
      boot.zfs.extraPools = [ "src" ];
      systemd.services.zfs-import-src.unitConfig.ConditionPathExists = "/var/lib/test-pool-ready";
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
        tenants.bas = {
          dataset = "src/friends/bas";
          quota = "256M";
          authorizedKeys = [ clientPublicKey ];
          allowedFrom = [
            nodes.host.networking.primaryIPAddress
            nodes.host.networking.primaryIPv6Address
          ];
        };
      };
      services.sanoid = {
        enable = true;
        datasets."src/offsite" = snapshotPolicy;
      };
      # The README's sender example, with this test's host name, pool, and host key.
      programs.ssh.knownHosts.host.publicKey = hostPublicKey;

      services.syncoid = {
        enable = true;
        sshKey = "/var/lib/syncoid/id_ed25519";
        # The default also grants snapshot, destroy, bookmark, and mount.
        localSourceAllow = [
          "send"
          "hold"
        ];
        commonArgs = [
          "--no-sync-snap"
          "--compress=none"
          "--delete-target-snapshots"
          "--sshoption=StrictHostKeyChecking=yes"
        ];
        commands."src/offsite" = {
          target = "zfs-tenant-joe@host:tank/friends/joe/offsite";
          recursive = true;
          sendOptions = "w";
        };
      };
    };

  testScript = ''
    import shlex

    gate = (
        "timeout 120 ssh -T -i /var/lib/syncoid/id_ed25519 -o IdentitiesOnly=yes "
        "-o BatchMode=yes -o StrictHostKeyChecking=yes zfs-tenant-joe@host"
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

    def push(node=sender, unit="syncoid-src-offsite", receiver=host):
        # services.syncoid units are Type=simple: wait for the run to end, then check how it ended.
        node.execute(f"systemctl start --wait {unit}.service")
        result = node.succeed(f"systemctl show -P Result {unit}.service").strip()
        if result != "success":
            print(node.execute(f"journalctl -u {unit}.service --no-pager -n 100")[1])
            print(receiver.execute("journalctl -t zfs-tenant --no-pager -n 60")[1])
            raise AssertionError("syncoid push failed; journals above")

    def run_sanoid(node):
        status, _ = node.execute("systemctl start --wait sanoid.service")
        if status != 0:
            print(node.execute("journalctl -u sanoid.service --no-pager -n 100")[1])
            raise AssertionError("sanoid failed; journal above")

    def stop_timers():
        sender.succeed("systemctl stop sanoid.timer syncoid-src-offsite.timer")
        host.succeed("systemctl stop sanoid.timer syncoid-tank-outgoing.timer")

    host.start(allow_reboot=True)
    sender.start(allow_reboot=True)
    host.wait_for_unit("sshd.service")
    sender.wait_for_unit("multi-user.target")
    stop_timers()

    with subtest("record the tested software versions"):
        for node in (host, sender):
            print(node.succeed(
                "zfs version && ${pkgs.sanoid}/bin/sanoid --version "
                "&& ${pkgs.sanoid}/bin/syncoid --version && uname -r"
            ))

    with subtest("pools, datasets, and delegation exist"):
        host.succeed("zpool create -f -O mountpoint=none tank /dev/vdb")
        host.succeed("touch /var/lib/test-pool-ready")
        host.succeed("zfs create -o mountpoint=/srv/host tank/host")
        host.succeed("echo host-secret > /srv/host/secret")
        host.succeed("systemctl restart zfs-tenant-setup-joe.service")
        # Setup failed at boot (no pool yet), so its zone never started.
        host.succeed("systemctl restart zfs-tenant-zone-joe.service")
        host.wait_until_succeeds(f"test -s {pid_file}")
        sender.succeed("zpool create -f -O mountpoint=/src src /dev/vdb")
        sender.succeed("touch /var/lib/test-pool-ready")
        sender.succeed("printf correcthorsebatterystaple > /root/pp")
        sender.succeed(
            "zfs create -o encryption=on -o keyformat=passphrase "
            "-o keylocation=file:///root/pp src/offsite"
        )
        sender.succeed("zfs create src/offsite/photos && zfs create src/offsite/docs")
        sender.succeed("head -c 2M /dev/urandom > /src/offsite/photos/a.jpg")
        sender.succeed("head -c 4M /dev/urandom > /src/offsite/docs/b.pdf")
        sender.succeed("zfs snapshot -r src/offsite@autosnap_1")
        sender.succeed("systemctl restart zfs-tenant-setup-bas.service zfs-tenant-zone-bas.service")
        sender.wait_until_succeeds("test -s /run/zfs-tenant/bas/holder.pid")
        host.succeed("printf host-test-passphrase > /root/pp")
        host.succeed(
            "zfs create -o encryption=on -o keyformat=passphrase "
            "-o keylocation=file:///root/pp -o mountpoint=/outgoing tank/outgoing"
        )
        host.succeed("zfs create tank/outgoing/photos && echo host-photo > /outgoing/photos/photo")
        # The README's key setup; pushes run only when the test asks for them.
        for node in (host, sender):
            node.succeed("install -d -m 700 -o syncoid -g syncoid /var/lib/syncoid")
            node.succeed(
                "install -m 400 -o syncoid -g syncoid ${./integration/client_key} /var/lib/syncoid/id_ed25519"
            )

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

    with subtest("inside its zone the kernel still enforces delegation"):
        # What a gate bug could reach: the tenant uid inside its namespace, no gate in between.
        # Destroying the root runs first, while it has no children for zfs to complain about.
        out = host.fail(as_tenant_in_zone("zfs destroy tank/friends/joe") + " 2>&1")
        assert "permission denied" in out, out
        host.succeed(as_tenant_in_zone("zfs create tank/friends/joe/zonetest"))
        for command in [
            "zfs snapshot tank/friends/joe@x",
            "zfs set quota=none tank/friends/joe",
            "zfs set filesystem_limit=none tank/friends/joe",
            "zfs set mountpoint=/mnt tank/friends/joe/zonetest",
            "zfs allow -u zfs-tenant-joe quota tank/friends/joe",
        ]:
            out = host.fail(as_tenant_in_zone(command) + " 2>&1")
            assert "permission denied" in out, (command, out)
        host.succeed(as_tenant_in_zone("zfs destroy tank/friends/joe/zonetest"))

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
            "zfs receive -F tank/friends/joe",
            "zfs receive -F tank/host",
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

    with subtest("an existing plaintext target survives a refused receive"):
        sender.succeed(ask_gate("zfs create tank/friends/joe/plain-existing"))
        host.succeed("zfs snapshot tank/friends/joe/plain-existing@keep")
        out = sender.fail(
            "zfs send -w src/offsite/docs@autosnap_3 | "
            + via_gate("zfs receive tank/friends/joe/plain-existing") + " 2>&1"
        )
        assert "is unencrypted" in out, out
        assert "plain-existing@keep" in snapshots("tank/friends/joe/plain-existing")
        sender.succeed(ask_gate("zfs destroy -r tank/friends/joe/plain-existing"))

    with subtest("the tenant can abort an interrupted receive"):
        sender.fail(
            "zfs send -w src/offsite/docs@autosnap_3 | head -c 1000000 | "
            + via_gate("zfs receive -s tank/friends/joe/abort")
        )
        row = sender.succeed(ask_gate("zfs get -H receive_resume_token tank/friends/joe/abort"))
        assert row.split("\t")[2] not in ("", "-"), row
        sender.succeed(ask_gate("zfs receive -A tank/friends/joe/abort"))
        host.fail("zfs list tank/friends/joe/abort")

    with subtest("filesystem limits stop creation and recover after cleanup"):
        count = int(host.succeed("zfs get -Hp -o value filesystem_count tank/friends/joe"))
        host.succeed(f"zfs set filesystem_limit={count + 1} tank/friends/joe")
        sender.succeed(ask_gate("zfs create tank/friends/joe/limit-one"))
        sender.fail(ask_gate("zfs create tank/friends/joe/limit-two"))
        host.fail("zfs list tank/friends/joe/limit-two")
        assert int(host.succeed("zfs get -Hp -o value filesystem_count tank/friends/joe")) == count + 1
        sender.succeed(ask_gate("zfs destroy tank/friends/joe/limit-one"))
        sender.succeed(ask_gate("zfs create tank/friends/joe/limit-two"))
        sender.succeed(ask_gate("zfs destroy tank/friends/joe/limit-two"))
        host.succeed("zfs set filesystem_limit=100 tank/friends/joe")

    with subtest("snapshot limits stop receives and recover after raising the limit"):
        sender.succeed("zfs create src/offsite/limit && zfs snapshot src/offsite/limit@one")
        count = int(host.succeed("zfs get -Hp -o value snapshot_count tank/friends/joe"))
        host.succeed(f"zfs set snapshot_limit={count + 1} tank/friends/joe")
        sender.succeed(
            "zfs send -w src/offsite/limit@one | "
            + via_gate("zfs receive tank/friends/joe/limit")
        )
        sender.succeed("zfs snapshot src/offsite/limit@two")
        transfer = (
            "zfs send -w -i src/offsite/limit@one src/offsite/limit@two | "
            + via_gate("zfs receive tank/friends/joe/limit")
        )
        sender.fail(transfer)
        assert "@one" in snapshots("tank/friends/joe/limit")
        assert "@two" not in snapshots("tank/friends/joe/limit")
        host.succeed("zfs set snapshot_limit=20000 tank/friends/joe")
        sender.succeed(transfer)
        assert "@two" in snapshots("tank/friends/joe/limit")
        sender.succeed(ask_gate("zfs destroy -r tank/friends/joe/limit"))
        sender.succeed("zfs destroy -r src/offsite/limit")

    with subtest("real sanoid snapshots replicate in both directions"):
        for node, source in ((sender, "src/offsite"), (host, "tank/outgoing")):
            run_sanoid(node)
            listing = node.succeed(f"zfs list -H -o name -t snapshot -r {source}")
            assert any(
                name.startswith(source + "@autosnap_") and name.endswith("_hourly")
                for name in listing.splitlines()
            ), listing
            assert any(
                name.startswith(source + "/photos@autosnap_") and name.endswith("_hourly")
                for name in listing.splitlines()
            ), listing
        push()
        push(host, "syncoid-tank-outgoing", sender)
        for source_node, source, destination_node, destination in (
            (sender, "src/offsite/photos", host, "tank/friends/joe/offsite/photos"),
            (host, "tank/outgoing/photos", sender, "src/friends/bas/outgoing/photos"),
        ):
            expected = source_node.succeed(f"zfs list -H -o name -t snapshot -r {source}")
            actual = destination_node.succeed(f"zfs list -H -o name -t snapshot -r {destination}")
            assert actual == expected.replace(source, destination), (expected, actual)
            assert destination_node.succeed(f"zfs get -H -o value keystatus {destination}").strip() == "unavailable"

    reverse_gate = (
        "timeout 120 ssh -T -i /var/lib/syncoid/id_ed25519 -o IdentitiesOnly=yes "
        "-o BatchMode=yes -o StrictHostKeyChecking=yes zfs-tenant-bas@sender"
    )
    with subtest("the reciprocal tenant is isolated and can restore its own data"):
        listing = host.succeed(f"{reverse_gate} 'zfs list -H -o name -r' </dev/null")
        assert "src/friends/bas/outgoing" in listing, listing
        assert "src/offsite" not in listing, listing
        out = host.fail(f"{reverse_gate} 'zfs list -r src/offsite' </dev/null 2>&1")
        assert "command not allowed" in out, out
        snap = host.succeed("zfs list -H -o name -t snapshot -r tank/outgoing/photos").splitlines()[0].split("@")[1]
        host.succeed(
            f"{reverse_gate} 'zfs send -w src/friends/bas/outgoing/photos@{snap}' </dev/null "
            "| zfs receive -u tank/restored"
        )
        host.succeed("zfs load-key -L file:///root/pp tank/restored")
        host.succeed("zfs set mountpoint=/restored tank/restored && zfs mount -a")
        host.succeed("cmp /restored/photo /outgoing/photos/photo")

    with subtest("sanoid prunes expired snapshots and syncoid mirrors the deletion"):
        expired = [f"autosnap_2000-01-01_0{hour}:00:00_hourly" for hour in range(4)]
        for snap in expired:
            # Sanoid sorts by creation seconds; give each fixture a distinct age.
            sender.succeed("date -s '+1 second'")
            sender.succeed(f"zfs snapshot -r src/offsite@{snap}")
        push()
        assert expired[0] in snapshots("tank/friends/joe/offsite/photos")
        # Retention uses actual creation times, not the dates in snapshot names.
        sender.succeed("date -s '+3 hours'")
        run_sanoid(sender)
        # Sanoid calculates the pruning candidates before creating this run's new snapshot.
        # A second normal cron run includes that snapshot when enforcing the count floor.
        run_sanoid(sender)
        local = sender.succeed("zfs list -H -o name -t snapshot -r src/offsite/photos")
        hourly = {name.split("@")[1] for name in local.splitlines() if name.endswith("_hourly")}
        assert len(hourly) == 2, local
        assert set(expired) - hourly, local
        sender.succeed("zfs snapshot -r src/offsite@after-prune")
        push()
        remote = snapshots("tank/friends/joe/offsite/photos")
        local = sender.succeed("zfs list -H -o name -t snapshot -r src/offsite/photos")
        assert remote == local.replace("src/offsite/photos", "tank/friends/joe/offsite/photos"), (local, remote)
        assert "@after-prune" in remote, remote

    with subtest("syncoid recovers a snapshot-only retention gap without manual cleanup"):
        source = "src/offsite/retention-gap"
        target = "tank/friends/joe/offsite/retention-gap"
        sender.succeed(f"zfs create {source} && zfs snapshot {source}@base")
        sender.succeed(f"zfs snapshot {source}@latest")
        push()
        guid = host.succeed(f"zfs get -H -o value guid {target}")
        # Model missed pushes: source retention deletes the newest shared snapshot,
        # while an older common snapshot and the receiver's newer snapshot survive.
        sender.succeed(f"zfs destroy {source}@latest && zfs snapshot {source}@next")
        push()
        actual = snapshots(target)
        assert "@base" in actual and "@next" in actual and "@latest" not in actual, actual
        assert host.succeed(f"zfs get -H -o value guid {target}") == guid

    with subtest("syncoid recovers a retention gap with changed data without reseeding"):
        sender.succeed(f"echo first > /{source}/payload && zfs snapshot {source}@with-data")
        push()
        sender.succeed(f"zfs destroy {source}@with-data && echo second > /{source}/payload")
        sender.succeed(f"zfs snapshot {source}@after-data")
        # Callers who omit -F still get a conservative receive with no rollback.
        out = sender.fail(
            f"zfs send -w -I {source}@next {source}@after-data | "
            + via_gate(f"zfs receive {target}") + " 2>&1"
        )
        assert "has been modified since most recent snapshot" in " ".join(out.split()), out
        assert "@with-data" in snapshots(target), snapshots(target)
        assert "@after-data" not in snapshots(target), snapshots(target)
        # Syncoid explicitly requests -F; existing receive delegation permits it.
        push()
        assert host.succeed(f"zfs get -H -o value guid {target}") == guid
        expected = sender.succeed(f"zfs list -H -o name -t snapshot -r {source}")
        assert snapshots(target) == expected.replace(source, target), (expected, snapshots(target))
        sender.succeed(
            f"{ask_gate(f'zfs send -w {target}@after-data')} | zfs receive -u src/gap-restored"
        )
        sender.succeed("zfs load-key -L file:///root/pp src/gap-restored && zfs mount src/gap-restored")
        sender.succeed(f"cmp /src/gap-restored/payload /{source}/payload")

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
        # The oversized source is only a quota fixture; later recursive pushes omit it.
        sender.succeed("zfs destroy -r src/offsite/big")

    with subtest("both machines recover their zones and replication after reboot"):
        boot_ids = {node.name: node.succeed("cat /proc/sys/kernel/random/boot_id").strip() for node in (host, sender)}
        sender_time = int(sender.succeed("date +%s"))
        host.reboot()
        sender.reboot()
        host.wait_for_unit("multi-user.target")
        sender.wait_for_unit("multi-user.target")
        for node in (host, sender):
            node.wait_until_succeeds(f"test $(cat /proc/sys/kernel/random/boot_id) != {boot_ids[node.name]}")
        # Preserve monotonic snapshot creation dates if reboot reset the advanced guest clock.
        sender.succeed(f"date -s @{sender_time + 60}")
        stop_timers()
        host.wait_for_unit("zfs-tenant-zone-joe.service")
        sender.wait_for_unit("zfs-tenant-zone-bas.service")
        host.wait_until_succeeds(f"test -s {pid_file}")
        sender.wait_until_succeeds("test -s /run/zfs-tenant/bas/holder.pid")
        assert "tank/friends/joe/offsite" in sender.succeed(ask_gate("zfs list -H -o name -r"))
        sender.succeed("zfs snapshot -r src/offsite@after-reboot")
        host.succeed("zfs snapshot -r tank/outgoing@after-reboot")
        push()
        push(host, "syncoid-tank-outgoing", sender)
        assert "@after-reboot" in snapshots("tank/friends/joe/offsite/photos")
        assert "@after-reboot" in sender.succeed("zfs list -H -o name -t snapshot -r src/friends/bas/outgoing/photos")
        assert host.succeed("zfs get -H -o value keystatus tank/friends/joe/offsite/photos").strip() == "unavailable"
        assert sender.succeed("zfs get -H -o value keystatus src/friends/bas/outgoing/photos").strip() == "unavailable"
        host.succeed("test -e /srv/host/secret")

        # Local sources can still be unlocked after raw replication with keys unloaded.
        sender.succeed("zfs load-key -L file:///root/pp src/offsite && zfs mount -a")
        host.succeed("zfs load-key -L file:///root/pp tank/outgoing && zfs mount -a")

  '';
}
