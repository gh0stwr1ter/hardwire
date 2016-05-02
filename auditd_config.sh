#!/bin/bash/
#
# First we backup the files we will be modifying.
cp /etc/rsyslog.conf /etc/rsyslog.bak
cp /etc/audisp/plugins.d/syslog.conf /etc/audisp/plugins.d/syslog.conf.bak
cp /etc/audit/audit.rules /etc/audit/audit.rules.bak
#
# Next we configure syslog.conf to allow us to disallow logging duplication in /var/log/messages.  
sed -i -e 's/no/yes/g' /etc/audisp/plugins.d/syslog.conf
sed -i -e 's/LOG_LOCAL0/LOG_LOCAL6/g' /etc/audisp/plugins.d/syslog.conf
#
# Disable audit logs being replicated to /var/log/messages for deduplication of events.
sed -i -e 's/*.info;mail.none;authpriv.none;cron.none/*.info;mail.none;authpriv.none;cron.none;local6.none/g' /etc/rsyslog.conf
#
# Now we configure other log files to be sent to our remote  logging  box.
sed -i -e 's/<ip_address>/<ip_address>/g' /etc/rsyslog.conf
echo "" > /etc/rsyslog.conf
echo '#Send audit.log events to QRadar.' > /etc/rsyslog.conf
echo "" > /etc/rsyslog.conf
sed -i 's/.*$ModLoad immark.*/&\n$ModLoad imfile/' /etc/rsyslog.conf
echo '$InputFileName /var/log/audit/audit.log' > /etc/rsyslog.conf
echo '$InputFileTag tag_audit_log:' > /etc/rsyslog.conf
echo '$InputFileStateFile audit_log' > /etc/rsyslog.conf
echo '$InputFileSeverity info' > /etc/rsyslog.conf
echo '$InputFileFacility local6' > /etc/rsyslog.conf
echo '$InputRunFileMonitor' > /etc/rsyslog.conf
echo 'local6.* @<ip_address>:514' > /etc/rsyslog.conf
echo "Remote logging configured...!"
# 
# Now we will add the audit rules for items that we watn to monitor.
#
echo "Applying audit configurations...."
echo "##- Use of privileged commands (unsuccessful and successful)" >> /etc/audit/audit.rules
for i in /bin /sbin /usr /var /opt
do
  find $i -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{ print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules
done
echo "" >> /etc/audit/audit.rules
echo "#DISA Monitoring Rules" >> /etc/audit/audit.rules
echo "" >> /etc/audit/audit.rules
echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S open -F success=0" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S open -F success=0" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S openat -F success=0" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S openat -F success=0" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S truncate -F success=0" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S truncate -F success=0" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S ftruncate -F success=0" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S ftruncate -F success=0" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S creat -F success=0" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S creat -F success=0" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S unlink -S rmdir" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S unlink -S rmdir" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S rmdir" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S rmdir" >> /etc/audit/audit.rules
echo "-w /usr/sbin/useradd -p x -k useradd" >> /etc/audit/audit.rules
echo "-w /usr/sbin/usermod -p x -k usermod" >> /etc/audit/audit.rules
echo "-w /usr/sbin/groupadd -p x -k groupadd" >> /etc/audit/audit.rules
echo "-w /usr/sbin/groupmod -p x -k groupmod" >> /etc/audit/audit.rules
echo "-w /etc/passwd -p a -k passwd" >> /etc/audit/audit.rules
echo "-w /etc/passwd -p w -k passwd" >> /etc/audit/audit.rules
echo "-w /etc/shadow -p a -k shadow" >> /etc/audit/audit.rules
echo "-w /etc/shadow -p w -k shadow" >> /etc/audit/audit.rules
echo "-w /etc/group -p a -k group" >> /etc/audit/audit.rules
echo "-w /etc/group -p w -k group" >> /etc/audit/audit.rules
echo "-w /etc/gshadow -p a -k gshadow" >> /etc/audit/audit.rules
echo "-w /etc/gshadow -p w -k gshadow" >> /etc/audit/audit.rules
echo "-w /usr/sbin/userdel -p x -k userdel" >> /etc/audit/audit.rules
echo "-w /usr/sbin/groupdel -p x -k groupdel" >> /etc/audit/audit.rules
echo "-w /usr/bin/passwd -p x -k passwd" >> /etc/audit/audit.rules
echo "-w /etc/audit.rules perm=rwxa -k audit" >> /etc/audit/audit.rules
echo "-w /etc/audit/audit.rules perm=rwxa -k audit" >> /etc/audit/audit.rules
echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/audit.rules
echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S adjtimex" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S adjtimex" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S settimeofday" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S settimeofday" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S stime" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S stime" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S clock_settime" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S clock_settime" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S sethostname" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sethostname" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S setdomainname" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S setdomainname" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sched_setparam" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S sched_setparam" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S sched_setscheduler" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S sched_setscheduler" >> /etc/audit/audit.rules
echo "-w /var/log/faillog perm=a -k LOG_faillog" >> /etc/audit/audit.rules
echo "-w /var/log/lastlog perm=a -k LOG_lastlog" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S fchmod" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S fchmod" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S fchmodat" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S fchmodat" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S chown32" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S chown32" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S fchown32" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S fchown32" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S lchown32" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S lchown32" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S chown" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S chown" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S fchownat" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S fchownat" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S setxattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S setxattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S lsetxattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S lsetxattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S fsetxattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S fsetxattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S removexattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S removexattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S lremovexattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S lremovexattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b64 -S fremovexattr" >> /etc/audit/audit.rules
echo "-a exit,always -F arch=b32 -S fremovexattr" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
echo "" >> /etc/audit/audit.rules
echo "#Additional Monitoring Rules" >> /etc/audit/audit.rules
echo "" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/auditd.conf -F perm=rwxa -k auditd_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/ssh/sshd_config -F perm=rwxa  -k ssh_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/audit/audit.rules -F perm=rwxa -k audit_rules_changes" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/logrotate.conf -F perm=rwxa -k log_rotate_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/rsyslog.conf -F perm=rwxa -k rsyslog_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/usr -F perm=a -k rootdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/tmp -F perm=a -k rootdir_perm_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log/messages -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log/wtmp -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log/secure -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/default -F perm=rwxa -k rootdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log/audit/audit.log -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/sbin/auditctl -F perm=a -k auditd_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/sbin/auditd -F perm=a -k auditd_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/sbin/ausearch -F perm=a -k auditd_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/syslog.conf -F perm=rwxa -k syslog_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/snmpd.conf -F perm=rwxa -k snmp_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/snmp/snmpd.conf -F perm=rwxa -k snmp_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/snmpd/snmpd.conf -F perm=rwxa -k snmp_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/root/.rhosts -F perm=rwxa -k rootdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/root/.netrc -F perm=rwxa -k rootdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/home/rusers/$USER/.ssh/authorized-keys -F perm=rwxa -k ssh_key_access" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/home/rusers/$USER/.ssh/authorized-keys2 -F perm=rwxa -k ssh_key_access" >> /etc/audit/audit.rules
echo "" >> /etc/audit/audit.rules
echo "Custom Monitoring Rules" >> /etc/audit/audit.rules
echo "" >> /etc/audit/audit.rules
echo "-w /etc/hosts perm=rwxa -k CFG_hosts" >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/network-scripts/" perm=rwxa -k CFG_network >> /etc/audit/audit.rules
echo "-w /etc/inittab perm=rwxa -k CFG_inittab" >> /etc/audit/audit.rules
echo "-w /etc/rc.d/init.d/ perm=rwxa -k CFG_initscripts" >> /etc/audit/audit.rules
echo "-w /etc/ld.so.conf perm=rwxa -k CFG_ld.so.conf" >> /etc/audit/audit.rules
echo "-w /etc/localtime perm=rwxa -k CFG_localtime" >> /etc/audit/audit.rules
echo "-w /etc/sysctl.conf perm=rwxa -k CFG_sysctl.conf" >> /etc/audit/audit.rules
echo "-w /etc/modprobe.conf perm=rwxa -k CFG_modprobe.conf" >> /etc/audit/audit.rules
echo "-w /etc/pam.d/ perm=rwxa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /etc/security/limits.conf perm=rwxa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /etc/security/pam_env.conf perm=rwxa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /etc/security/namespace.conf perm=rwxa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /etc/security/namespace.init perm=rwxa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /var/log/tallylog perm=a -k LOG_tallylog" >> /etc/audit/audit.rules
echo "-w /etc/security/opasswd -k CFG_opasswd" >> /etc/audit/audit.rules
echo "-w /etc/login.defs perm=rwxa -k CFG_login.defs" >> /etc/audit/audit.rules
echo "-w /etc/securetty perm=rwxa -k CFG_securetty" >> /etc/audit/audit.rules
echo "-w /etc/cron.d/ perm=rwxa -k CFG_cron.d" >> /etc/audit/audit.rules
echo "-w /etc/cron.daily/ perm=rwxa -k CFG_cron.daily" >> /etc/audit/audit.rules
echo "-w /etc/cron.hourly/ perm=rwxa -k CFG_cron.hourly" >> /etc/audit/audit.rules
echo "-w /etc/cron.monthly/ perm=rwxa -k CFG_cron.monthly" >> /etc/audit/audit.rules
echo "-w /etc/cron.weekly/ perm=rwxa -k CFG_cron.weekly" >> /etc/audit/audit.rules
echo "-w /etc/crontab perm=rwxa -k CFG_crontab" >> /etc/audit/audit.rules
echo "-w /var/spool/cron/root -k CFG_crontab_root" >> /etc/audit/audit.rules
echo "-w /etc/group perm=rwxa -k CFG_group" >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/auditd perm=rwxa -k CFG_auditd.conf" >> /etc/audit/audit.rules
echo "-w /etc/libaudit.conf perm=rwxa -k CFG_libaudit.conf" >> /etc/audit/audit.rules
echo "-w /etc/cron.allow perm=rwxa -k CFG_cron.allow" >> /etc/audit/audit.rules
echo "-w /etc/cron.deny perm=rwxa -k CFG_cron.deny" >> /etc/audit/audit.rules
echo "-w /etc/resolv.conf perm=rwxa -k CFG_hosts" >> /etc/audit/audit.rules
echo "-w /boot perm=wa -k Boot_Monitor" >> /etc/audit/audit.rules
echo "-w /etc/sudoers -p wa -k admin_actions" >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/iptables perm=wa -k IPtables_Mod" >> /etc/audit/audit.rules
echo "-a always,exit -F arch=ARCH -S unlink -S unlinkat -S rename -S renameat -F auid>=500 \-F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
echo
echo " Restarting services..."
/etc/init.d/auditd restart
/etc/init.d/rsyslog restart
echo "Services started"
#Increase the backlog_limit
auditctl -b 1024
#Make the audit configuration immutable
auditctl -e 2
echo "Rule configuration complete!"
echo
echo ===================================================
echo
echo "Audit configuration complete!"
