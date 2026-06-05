control 'SV-281027' do
  title 'RHEL 10 must be configured so that the "/etc/passwd-" file is owned by "root".'
  desc 'The "/etc/passwd-" file is a backup file of "/etc/passwd", and as such contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/passwd-" file is owned by "root" with the following command:

$ sudo stat -c "%U %n" /etc/passwd-
root /etc/passwd-

If the "/etc/passwd-" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the owner of the "/etc/passwd-" file is set to "root" by running the following command:

$ sudo chown root /etc/passwd-'
  impact 0.5
  tag check_id: 'C-85588r1165434_chk'
  tag severity: 'medium'
  tag gid: 'V-281027'
  tag rid: 'SV-281027r1165436_rule'
  tag stig_id: 'RHEL-10-400050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85493r1165435_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe file('/etc/passwd-') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
