control 'SV-281035' do
  title 'RHEL 10 must be configured so that the "/var/log/"messages file is owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 10 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify RHEL 10 is configured so that the "/var/log/messages" file is owned by root with the following command:

$ stat -c "%U %n" /var/log/messages
root /var/log/messages

If "/var/log/messages" does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the owner of the "/var/log/messages" file is set to "root" by running the following command:

$ sudo chown root /var/log/messages'
  impact 0.5
  tag check_id: 'C-85596r1165458_chk'
  tag severity: 'medium'
  tag gid: 'V-281035'
  tag rid: 'SV-281035r1165460_rule'
  tag stig_id: 'RHEL-10-400090'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-85501r1165459_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
