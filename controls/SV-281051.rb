control 'SV-281051' do
  title 'RHEL 10 must enforce "root" ownership of the audit log directory to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

'
  desc 'check', %q(Verify RHEL 10 audit logs directory is owned by "root".

Determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the location of the audit log file, determine if the audit log directory is owned by "root" using the following command:

$ sudo stat -c '%U %n' /var/log/audit
root /var/log/audit

If the audit log directory is not owned by "root", this is a finding.)
  desc 'fix', 'Configure RHEL 10 to prevent unauthorized read access by ensuring the audit log directory is "root" owned with the following command:

$ sudo chown root /var/log/audit'
  impact 0.5
  tag check_id: 'C-85612r1165506_chk'
  tag severity: 'medium'
  tag gid: 'V-281051'
  tag rid: 'SV-281051r1165508_rule'
  tag stig_id: 'RHEL-10-400170'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-85517r1165507_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'SI-11 b']
end
