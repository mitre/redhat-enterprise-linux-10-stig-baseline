control 'SV-281030' do
  title 'RHEL 10 must be configured so that the "/etc/shadow" file is group-owned by "root".'
  desc 'The "/etc/shadow" file stores password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/shadow" file is group-owned by "root" with the following command:

$ sudo stat -c "%G %n" /etc/shadow
root /etc/shadow

If the "/etc/shadow" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the group of the "/etc/shadow" file is set to "root" by running the following command:

$ sudo chgrp root /etc/shadow'
  impact 0.5
  tag check_id: 'C-85591r1165443_chk'
  tag severity: 'medium'
  tag gid: 'V-281030'
  tag rid: 'SV-281030r1165445_rule'
  tag stig_id: 'RHEL-10-400065'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85496r1165444_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe file('/etc/shadow') do
    it { should exist }
    its('group') { should cmp 'root' }
  end
end
