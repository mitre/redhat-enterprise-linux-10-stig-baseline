control 'SV-281021' do
  title 'RHEL 10 must be configured so that the "/etc/gshadow" file is owned by "root".'
  desc 'The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/gshadow" file is owned by "root" with the following command:

$ sudo stat -c "%U %n" /etc/gshadow
root /etc/gshadow

If the "/etc/gshadow" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the owner of the file "/etc/gshadow" is set to "root" by running the following command:

$ sudo chown root /etc/gshadow'
  impact 0.5
  tag check_id: 'C-85582r1165416_chk'
  tag severity: 'medium'
  tag gid: 'V-281021'
  tag rid: 'SV-281021r1165418_rule'
  tag stig_id: 'RHEL-10-400020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85487r1165417_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  describe file('/etc/gshadow') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
