control 'SV-281050' do
  title 'RHEL 10 must enforce group ownership of audit logs by "root" or by a restricted logging group to prevent unauthorized read access.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

'
  desc 'check', 'Verify RHEL 10 audit logs are group-owned by "root" or a restricted logging group.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Using the location of the audit log file, determine if the audit log is group-owned by "root" using the following command:

$ sudo stat -c "%G %n" /var/log/audit/audit.log
root /var/log/audit/audit.log

If the audit log is not group-owned by "root" or the configured alternative logging group, this is a finding.'
  desc 'fix', %q(Configure RHEL 10 to prevent unauthorized read access by ensuring that audit logs are group-owned by root or by a restricted logging group.

Change the group of the directory of "/var/log/audit" to be owned by a correct group.

Identify the group that is configured to own audit logs:

$ sudo grep -P '^[ ]*log_group[ ]+=.*$' /etc/audit/auditd.conf

Change the ownership to that group:

$ sudo chgrp ${GROUP} /var/log/audit)
  impact 0.5
  tag check_id: 'C-85611r1184684_chk'
  tag severity: 'medium'
  tag gid: 'V-281050'
  tag rid: 'SV-281050r1184685_rule'
  tag stig_id: 'RHEL-10-400165'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-85516r1165504_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029', 'SRG-OS-000206-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-001314']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'SI-11 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe file(auditd_conf('/etc/audit/auditd.conf').log_file) do
    its('group') { should be_in input('var_log_audit_group') }
  end
end
