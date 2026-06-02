control 'SV-281055' do
  title 'RHEL 10 must enforce the audit log directory to have a mode of "0750" or less permissive to prevent unauthorized read access.'
  desc 'If users can write to audit logs, audit trails can be modified or destroyed.

'
  desc 'check', 'Verify RHEL 10 enforces the audit log directory to have a mode of "0750" or less permissive to prevent unauthorized read access.

Determine where the audit logs are stored with the following command:

$ sudo grep "^log_file" /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Find the group that owns audit logs:

$ sudo grep "^log_group" /etc/audit/auditd.conf
log_group = root

Run the following command to check the mode of the system audit logs:

$ sudo stat -c "%a %n" [audit_log_directory]

Replace "[audit_log_directory]" to the correct audit log directory path; by default this location is "/var/log/audit".

If the log_group is "root" or is not set, the correct permissions are "0700".
 
If the log_group is owned by anyone other than "root", the correct permissions are "0750".

If audit logs have a more permissive mode than is required, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the audit log directories have a mode of "0750" or less permissive to prevent unauthorized read access with the following command:

$ sudo chmod 0700 /var/log/audit

Note: The correct permissions are "0700" if the directory is owned by "root"; otherwise, the correct permissions are "0750".

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85616r1165518_chk'
  tag severity: 'medium'
  tag gid: 'V-281055'
  tag rid: 'SV-281055r1165520_rule'
  tag stig_id: 'RHEL-10-400190'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-85521r1165519_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
