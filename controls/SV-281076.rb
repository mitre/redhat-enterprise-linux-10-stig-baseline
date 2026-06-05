control 'SV-281076' do
  title 'RHEL 10 must enforce mode "0000" for "/etc/shadow" to prevent unauthorized access.'
  desc 'The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to "root" provides the designated owner with access to sensitive information, which could weaken the system security posture.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/shadow" file has mode "0000" with the following command:

$ sudo stat -c "%a %n" /etc/shadow
0 /etc/shadow

If a value of "0" is not returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enforce mode "0000" for "/etc/shadow" to prevent unauthorized access.

Change the mode of the file "/etc/shadow" to "0000" by running the following command:

$ sudo chmod 0000 /etc/shadow'
  impact 0.5
  tag check_id: 'C-85637r1165581_chk'
  tag severity: 'medium'
  tag gid: 'V-281076'
  tag rid: 'SV-281076r1165583_rule'
  tag stig_id: 'RHEL-10-400295'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85542r1165582_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  system_file = '/etc/shadow'

  mode = input('expected_modes')[system_file]

  describe file(system_file) do
    it { should exist }
    it { should_not be_more_permissive_than(mode) }
  end
end
