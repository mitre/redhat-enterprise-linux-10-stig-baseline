control 'SV-281034' do
  title 'RHEL 10 must be configured so that the "/var/log" directory is group-owned by "root".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 10 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify RHEL 10 is configured so that the "/var/log" directory is group-owned by "root" with the following command:

$ stat -c "%G %n" /var/log
root /var/log

If "/var/log" does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the group owner of the directory "/var/log" is set to "root" by running the following command:

$ sudo chgrp root /var/log'
  impact 0.5
  tag check_id: 'C-85595r1165455_chk'
  tag severity: 'medium'
  tag gid: 'V-281034'
  tag rid: 'SV-281034r1165457_rule'
  tag stig_id: 'RHEL-10-400085'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-85500r1165456_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/var/log') do
    it { should exist }
    its('group') { should eq 'root' }
  end
end
