control 'SV-281067' do
  title 'RHEL 10 must enforce mode "0644" or less permissive for the "/etc/group-" file to prevent unauthorized access.'
  desc 'The "/etc/group-" file is a backup file of "/etc/group", and as such contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/group-" file has mode "0644" or less permissive with the following command:

$ sudo stat -c "%a %n" /etc/group-
644 /etc/group-

If a value of "0644" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the mode of the "/etc/group-" file is set to "0644" by running the following command:

$ sudo chmod 0644 /etc/group-'
  impact 0.5
  tag check_id: 'C-85628r1165554_chk'
  tag severity: 'medium'
  tag gid: 'V-281067'
  tag rid: 'SV-281067r1165556_rule'
  tag stig_id: 'RHEL-10-400250'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85533r1165555_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  system_file = '/etc/group-'

  mode = input('expected_modes')[system_file]

  describe file(system_file) do
    it { should exist }
    it { should_not be_more_permissive_than(mode) }
  end
end
