control 'SV-281061' do
  title 'RHEL 10 must enforce mode "0755" or less permissive for the "/var/log" directory.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the RHEL 10 system or platform. Additionally, personally identifiable information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify RHEL 10 is configured so that the "/var/log" directory has a mode of "0755" or less permissive with the following command:

$ stat -c '%a %n' /var/log
755 /var/log

If "/var/log" does not have a mode of "0755" or less permissive, this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that the "/var/log" directory has a mode of "0755" by running the following command:

$ sudo chmod 0755 /var/log'
  impact 0.5
  tag check_id: 'C-85622r1165536_chk'
  tag severity: 'medium'
  tag gid: 'V-281061'
  tag rid: 'SV-281061r1165538_rule'
  tag stig_id: 'RHEL-10-400220'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-85527r1165537_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
