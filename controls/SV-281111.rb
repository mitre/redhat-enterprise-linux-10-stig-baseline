control 'SV-281111' do
  title 'RHEL 10 must periodically flush audit records to disk to ensure that audit records are not lost.'
  desc 'If option "freq" is not set to a value that requires audit records to be written to disk after a threshold number is reached, audit records may be lost.'
  desc 'check', 'Verify RHEL 10 is configured to flush audit records to disk after every 100 records with the following command:

$ sudo grep freq /etc/audit/auditd.conf
freq = 100

If "freq" is not set to a value of "100" or greater, the value is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to flush audit records to disk by adding or updating the following rule in "/etc/audit/rules.d/audit.rules":

freq = 100

Restart the audit daemon with the following command for changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85672r1166283_chk'
  tag severity: 'medium'
  tag gid: 'V-281111'
  tag rid: 'SV-281111r1166285_rule'
  tag stig_id: 'RHEL-10-500125'
  tag gtitle: 'SRG-OS-000051-GPOS-00024'
  tag fix_id: 'F-85577r1166284_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
