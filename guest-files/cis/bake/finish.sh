#!/bin/bash
# finish.sh - the CIS bake's second boot (pvs-cis-finish.service): the bake account goes,
# the check runs on the hardened and rebooted system, then the gold is generalized and the
# studio gets BAKE-OK. Runs once; the units remove themselves.
set -u
# Not in the first boot (an image may start the unit as soon as it is enabled): the next one.
[ "$(cat /proc/sys/kernel/random/boot_id)" = "$(cat /etc/pvs-cis/boot1.id 2>/dev/null)" ] && exit 0
R=/run/pvs-bake.report
LEVEL=$(cat /etc/pvs-cis/level 2>/dev/null || echo 1)
# The first boot's report (kernel, packages, locales - its /run is gone), then its fix summary.
if [ -f /etc/pvs-cis/boot1.report ]; then
    { cat /etc/pvs-cis/boot1.report; cat "$R" 2>/dev/null; } > "$R.new" && mv "$R.new" "$R"
    rm -f /etc/pvs-cis/boot1.report
else
    echo "BAKE-DIAG no first-boot report; /etc/pvs-cis has: $(ls /etc/pvs-cis | tr '\n' ' ')" >> "$R"
fi
rm -f /etc/pvs-cis/boot1.id
grep -E '^CIS-FIX-(FAILED|DONE)' /etc/pvs-cis/fix.log >> "$R" 2>/dev/null
rm -f /etc/pvs-cis/fix.log
[ -f /etc/pvs-cis/layout.failed ] && echo "BAKE-LAYOUT-FAILED $(cat /etc/pvs-cis/layout.failed)" >> "$R"
# Level 2: what became of the layout unit - its state and its own output, for the bake log.
if [ -f /etc/pvs-cis/layout.wanted ] && [ ! -f /etc/pvs-cis/layout.done ]; then
    echo "BAKE-DIAG layout unit: $(systemctl show -p ActiveState,SubState,Result,ExecMainStatus,ConditionResult pvs-cis-layout.service 2>&1 | tr '\n' ' ')" >> "$R"
    journalctl -b -u pvs-cis-layout.service --no-pager -o cat 2>&1 | tail -n 15 | sed 's/^/BAKE-DIAG | /' >> "$R"
fi
echo "BAKE-CIS-CHECKING level $LEVEL" >> "$R"
# What the check must not see: the bake's own account and its NOPASSWD sudo.
userdel -f -r bake 2>/dev/null
rm -f /etc/sudoers.d/90-cloud-init-users
mkdir -p /run/pvs-cis
chmod 0700 /run/pvs-cis
# The GRUB password, kept on disk across the reboot only for the studio to collect.
if [ -f /root/.pvs-cis-grub-password ]; then
    cp /root/.pvs-cis-grub-password /run/pvs-cis/grub-password
    shred -u /root/.pvs-cis-grub-password 2>/dev/null || rm -f /root/.pvs-cis-grub-password
fi
/usr/local/sbin/pvs-cis check --level "$LEVEL" --exceptions /etc/pvs-cis/exceptions \
    --json /run/pvs-cis/report.json 2>/run/pvs-cis/check.log | tee -a "$R"
# Once only: this unit and the layout one go; the gold's own first-boot units are switched on
# (they do nothing in the bake - they start with the clone).
systemctl disable pvs-cis-finish.service pvs-cis-layout.service >/dev/null 2>&1
rm -f /etc/systemd/system/pvs-cis-finish.service /etc/systemd/system/pvs-cis-layout.service
systemctl enable pvs-cis-aide-init.service >/dev/null 2>&1
[ -e /etc/pvs-cis/layout.done ] && systemctl enable pvs-cis-grow.service >/dev/null 2>&1
echo BAKE-CIS-SEALING >> "$R"
bash /usr/local/lib/pvs-cis/generalize.sh
sync
echo BAKE-OK >> "$R"
