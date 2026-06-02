control 'SV-281099' do
  title 'RHEL 10 must write audit records to disk.'
  desc 'Audit data must be synchronously written to disk to ensure log integrity. This setting ensures that all audit event data is written to disk.'
  desc 'check', 'Verify the RHEL 10 audit system is configured to write logs to the disk with the following command:

$ sudo grep write_logs /etc/audit/auditd.conf
write_logs = yes

If "write_logs" does not have a value of "yes", the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure the RHEL 10 audit system to write log files to the disk.

Edit the "/etc/audit/auditd.conf" file and add or update the "write_logs" option to "yes":

write_logs = yes

Restart the audit daemon with the following command for changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85660r1165650_chk'
  tag severity: 'medium'
  tag gid: 'V-281099'
  tag rid: 'SV-281099r1165652_rule'
  tag stig_id: 'RHEL-10-500015'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-85565r1165651_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000163']
  tag nist: ['CM-6 b', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe auditd_conf do
    its('write_logs.upcase') { should cmp 'YES' }
  end
end
