control 'SV-281069' do
  title 'RHEL 10 must enforce mode "0000" or less permissive for the "/etc/gshadow-" file to prevent unauthorized access.'
  desc 'The "/etc/gshadow-" file is a backup of "/etc/gshadow", and as such contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/gshadow-" file has mode "0000" with the following command:

$ sudo stat -c "%a %n" /etc/gshadow-
0 /etc/gshadow-

If a value of "0" is not returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the mode of the "/etc/gshadow-" file is set to "0000" by running the following command:

$ sudo chmod 0000 /etc/gshadow-'
  impact 0.5
  tag check_id: 'C-85630r1165560_chk'
  tag severity: 'medium'
  tag gid: 'V-281069'
  tag rid: 'SV-281069r1165562_rule'
  tag stig_id: 'RHEL-10-400260'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85535r1165561_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  system_file = '/etc/gshadow-'

  mode = input('expected_modes')[system_file]

  describe file(system_file) do
    it { should exist }
    it { should_not be_more_permissive_than(mode) }
  end
end
