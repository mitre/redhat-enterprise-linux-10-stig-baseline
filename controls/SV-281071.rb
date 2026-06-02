control 'SV-281071' do
  title 'RHEL 10 must enforce mode "0644" or less permissive for "/etc/passwd-" file to prevent unauthorized access.'
  desc 'The "/etc/passwd-" file is a backup file of "/etc/passwd", and as such contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/passwd-" file has mode "0644" or less permissive with the following command:

$ sudo stat -c "%a %n" /etc/passwd-
644 /etc/passwd-

If a value of "0644" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the mode of the "/etc/passwd-" file is set to "0644" by running the following command:

$ sudo chmod 0644 /etc/passwd-'
  impact 0.5
  tag check_id: 'C-85632r1165566_chk'
  tag severity: 'medium'
  tag gid: 'V-281071'
  tag rid: 'SV-281071r1165568_rule'
  tag stig_id: 'RHEL-10-400270'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85537r1165567_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000213']
  tag nist: ['CM-6 b', 'AC-3']
  tag 'host'
  tag 'container'

  system_file = '/etc/group'

  mode = input('expected_modes')[system_file]

  describe file(system_file) do
    it { should exist }
    it { should_not be_more_permissive_than(mode) }
  end
end
