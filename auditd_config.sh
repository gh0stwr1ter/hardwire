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
# Now we configure other log files to be sent to our remote syslog server.
echo '#Send authpriv to remote syslog server.' >> /etc/rsyslog.conf
echo "" >> /etc/rsyslog.conf
echo 'authpriv.* @<IP_ADDRESS>:514' >> /etc/rsyslog.conf
echo "" >> /etc/rsyslog.conf
echo '#Send audit.log events to remote syslog server.' >> /etc/rsyslog.conf
echo "" >> /etc/rsyslog.conf
sed -i 's/.*$ModLoad immark.*/&\n$ModLoad imfile/' /etc/rsyslog.conf
echo '$InputFileName /var/log/audit/audit.log' >> /etc/rsyslog.conf
echo '$InputFileTag tag_audit_log:' >> /etc/rsyslog.conf
echo '$InputFileStateFile audit_log' >> /etc/rsyslog.conf
echo '$InputFileSeverity info' >> /etc/rsyslog.conf
echo '$InputFileFacility local6' >> /etc/rsyslog.conf
echo '$InputRunFileMonitor' >> /etc/rsyslog.conf
echo 'local6.* @<IP_ADDRESS>:514' >> /etc/rsyslog.conf
echo "Remote logging configured...!"
# 
# Now we will add the audit rules for items that we want to monitor.
#
echo "Applying audit configurations...."
echo "##- Use of privileged commands (unsuccessful and successful)" >> /etc/audit/audit.rules
for i in /bin /sbin /usr /var /opt
do
  find $i -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{ print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }' >> /etc/audit/audit.rules
done
echo "" >> /etc/audit/audit.rules
echo "#STIG Monitoring Rules" >> /etc/audit/audit.rules
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
echo "-w /etc/audit.rules -p wa -k audit" >> /etc/audit/audit.rules
echo "-w /etc/audit/audit.rules -p wa -k audit" >> /etc/audit/audit.rules
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
echo "-w /var/log/faillog -p wa -k LOG_faillog" >> /etc/audit/audit.rules
echo "-w /var/log/lastlog -p wa -k LOG_lastlog" >> /etc/audit/audit.rules
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
echo "-a exit,always -F path=/etc/auditd.conf -F perm=wa -k auditd_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/ssh/sshd_config -F perm=wa  -k ssh_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/audit/audit.rules -F perm=wa -k audit_rules_changes" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/logrotate.conf -F perm=wa -k log_rotate_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/rsyslog.conf -F perm=wa -k rsyslog_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/usr -F perm=a -k rootdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/tmp -F perm=a -k rootdir_perm_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log/messages -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log/wtmp -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log/secure -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/default -F perm=wa -k rootdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/var/log/audit/audit.log -F perm=a -k logdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/sbin/auditctl -F perm=a -k auditd_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/sbin/auditd -F perm=a -k auditd_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/sbin/ausearch -F perm=a -k auditd_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/syslog.conf -F perm=wa -k syslog_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/snmpd.conf -F perm=wa -k snmp_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/snmp/snmpd.conf -F perm=wa -k snmp_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/etc/snmpd/snmpd.conf -F perm=wa -k snmp_config_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/root/.rhosts -F perm=wa -k rootdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/root/.netrc -F perm=wa -k rootdir_permission_change" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/home/rusers/$USER/.ssh/authorized-keys -F perm=wa -k ssh_key_access" >> /etc/audit/audit.rules
echo "-a exit,always -F path=/home/rusers/$USER/.ssh/authorized-keys2 -F perm=wa -k ssh_key_access" >> /etc/audit/audit.rules
echo "-w /etc/hosts -p wa -k CFG_hosts" >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/network-scripts/" -p wa -k CFG_network >> /etc/audit/audit.rules
echo "-w /etc/inittab -p wa -k CFG_inittab" >> /etc/audit/audit.rules
echo "-w /etc/rc.d/init.d/ -p wa -k CFG_initscripts" >> /etc/audit/audit.rules
echo "-w /etc/ld.so.conf -p wa -k CFG_ld.so.conf" >> /etc/audit/audit.rules
echo "-w /etc/localtime -p wa -k CFG_localtime" >> /etc/audit/audit.rules
echo "-w /etc/sysctl.conf -p wa -k CFG_sysctl.conf" >> /etc/audit/audit.rules
echo "-w /etc/modprobe.conf -p wa -k CFG_modprobe.conf" >> /etc/audit/audit.rules
echo "-w /etc/pam.d/ -p wa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /etc/security/limits.conf -p wa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /etc/security/pam_env.conf -p wa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /etc/security/namespace.conf -p wa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /etc/security/namespace.init -p wa -k CFG_pam" >> /etc/audit/audit.rules
echo "-w /var/log/tallylog -p wa -k LOG_tallylog" >> /etc/audit/audit.rules
echo "-w /etc/security/opasswd -k CFG_opasswd" >> /etc/audit/audit.rules
echo "-w /etc/login.defs -p wa -k CFG_login.defs" >> /etc/audit/audit.rules
echo "-w /etc/securetty -p wa -k CFG_securetty" >> /etc/audit/audit.rules
echo "-w /etc/cron.d/ -p wa -k CFG_cron.d" >> /etc/audit/audit.rules
echo "-w /etc/cron.daily/ -p wa -k CFG_cron.daily" >> /etc/audit/audit.rules
echo "-w /etc/cron.hourly/ -p wa -k CFG_cron.hourly" >> /etc/audit/audit.rules
echo "-w /etc/cron.monthly/ -p wa -k CFG_cron.monthly" >> /etc/audit/audit.rules
echo "-w /etc/cron.weekly/ -p wa -k CFG_cron.weekly" >> /etc/audit/audit.rules
echo "-w /etc/crontab -p wa -k CFG_crontab" >> /etc/audit/audit.rules
echo "-w /var/spool/cron/root -k CFG_crontab_root" >> /etc/audit/audit.rules
echo "-w /etc/group -p wa -k CFG_group" >> /etc/audit/audit.rules
echo "-w /etc/sysconfig/auditd -p wa -k CFG_auditd.conf" >> /etc/audit/audit.rules
echo "-w /etc/libaudit.conf -p wa -k CFG_libaudit.conf" >> /etc/audit/audit.rules
echo "-w /etc/cron.allow -p wa -k CFG_cron.allow" >> /etc/audit/audit.rules
echo "-w /etc/cron.deny -p wa -k CFG_cron.deny" >> /etc/audit/audit.rules
# Increase the backlog_limit
auditctl -b 1024
#Make the audit configuration immutable
auditctl -e 2
echo "Rule configuration complete!"
echo
echo " Restarting services..."
/etc/init.d/auditd restart
/etc/init.d/rsyslog restart
echo "Services started"
echo ===================================================
echo
echo "Auditd configuration complete!"

