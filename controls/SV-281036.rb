control 'SV-281036' do
  title 'RHEL 10 must be configured so that the "/var/log/messages" file is group-owned by "root".'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 10 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify RHEL 10 is configured so that the "/var/log/messages" file is group-owned by "root" with the following command:

$ stat -c "%G %n" /var/log/messages
root /var/log/messages

If "/var/log/messages" does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the group owner of the "/var/log/messages" file is set to "root" by running the following command:

$ sudo chgrp root /var/log/messages'
  impact 0.5
  tag check_id: 'C-85597r1165461_chk'
  tag severity: 'medium'
  tag gid: 'V-281036'
  tag rid: 'SV-281036r1165463_rule'
  tag stig_id: 'RHEL-10-400095'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-85502r1165462_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
