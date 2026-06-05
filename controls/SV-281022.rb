control 'SV-281022' do
  title 'RHEL 10 must be configured so that the "/etc/gshadow" file is group-owned by "root".'
  desc 'The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/gshadow" file is group-owned by "root" with the following command:

$ sudo stat -c "%G %n" /etc/gshadow
root /etc/gshadow

If the "/etc/gshadow" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the group of the "/etc/gshadow" file is set to "root" by running the following command:

$ sudo chgrp root /etc/gshadow'
  impact 0.5
  tag check_id: 'C-85583r1165419_chk'
  tag severity: 'medium'
  tag gid: 'V-281022'
  tag rid: 'SV-281022r1165421_rule'
  tag stig_id: 'RHEL-10-400025'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85488r1165420_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe file('/etc/gshadow') do
    it { should exist }
    its('group') { should cmp 'root' }
  end
end
