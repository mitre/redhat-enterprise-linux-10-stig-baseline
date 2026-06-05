control 'SV-281053' do
  title 'RHEL 10 must enforce group ownership by "root" or a restricted logging group for audit log files to prevent unauthorized access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

'
  desc 'check', %q(Verify RHEL 10 enforces group ownership by "root" or a restricted logging group for audit log files to prevent unauthorized access.

Determine where the audit logs are stored with the following command:

$ sudo grep "^log_file" /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Determine the audit log group by running the following command:

$ sudo grep -P '^[ ]*log_group[ ]+=.*$' /etc/audit/auditd.conf
log_group = root

Check that the audit log file is owned by the correct group. Run the following command to display the owner of the audit log file:

$ sudo stat -c "%n %G" /var/log/audit/audit.log
/var/log/audit/audit.log root

The audit log file must be owned by the "log_group" or by "root" if the "log_group" is not specified.

If audit log files are owned by the incorrect group, this is a finding.)
  desc 'fix', %q(Configure RHEL 10 to enforce group ownership by "root" or a restricted logging group for audit log files to prevent unauthorized access.

Identify the group that is configured to own the audit log:

$ sudo grep -P '^[ ]*log_group[ ]+=.*$' /etc/audit/auditd.conf

Change the ownership to that group using the following command:

$ sudo chgrp ${log_group} ${log_file})
  impact 0.5
  tag check_id: 'C-85614r1165512_chk'
  tag severity: 'medium'
  tag gid: 'V-281053'
  tag rid: 'SV-281053r1165514_rule'
  tag stig_id: 'RHEL-10-400180'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-85519r1165513_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'SI-11 b']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe file(auditd_conf('/etc/audit/auditd.conf').log_file) do
    its('group') { should be_in input('var_log_audit_group') }
  end
end
