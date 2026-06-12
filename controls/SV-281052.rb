control 'SV-281052' do
  title 'RHEL 10 must enforce "root" ownership of audit logs to prevent unauthorized access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

'
  desc 'check', 'Verify RHEL 10 enforces "root" ownership of audit logs to prevent unauthorized access.

Determine where the audit logs are stored with the following command:

$ sudo grep "^log_file" /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the location of the audit log file, determine if the audit log files are owned by "root" using the following command:

$ sudo ls -la /var/log/audit/audit.log
rw-------. 2 root root 237923 Jun 11 11:56 /var/log/audit/audit.log

If the audit logs are not owned by "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enforce "root" ownership of audit logs to prevent unauthorized access with the following command:

$ sudo chown root [audit_log_file]

Replace "[audit_log_file]" with the correct audit log path. By default this location is "/var/log/audit/audit.log".'
  impact 0.5
  tag check_id: 'C-85613r1165509_chk'
  tag severity: 'medium'
  tag gid: 'V-281052'
  tag rid: 'SV-281052r1165511_rule'
  tag stig_id: 'RHEL-10-400175'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-85518r1165510_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  log_file = auditd_conf('/etc/audit/auditd.conf').log_file

  describe file(log_file) do
    its('owner') { should eq 'root' }
  end
end
