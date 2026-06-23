control 'SV-281031' do
  title 'RHEL 10 must be configured so that the "/etc/shadow-" file is owned by "root".'
  desc 'The "/etc/shadow-" file is a backup file of "/etc/shadow", and as such contains the list of local system accounts and password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/shadow-" file is owned by "root" with the following command:

$ sudo stat -c "%U %n" /etc/shadow-
root /etc/shadow-

If the "/etc/shadow-" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the owner of the "/etc/shadow-" file is set to "root" by running the following command:

$ sudo chown root /etc/shadow-'
  impact 0.5
  tag check_id: 'C-85592r1165446_chk'
  tag severity: 'medium'
  tag gid: 'V-281031'
  tag rid: 'SV-281031r1165448_rule'
  tag stig_id: 'RHEL-10-400070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85497r1165447_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  describe file('/etc/shadow-') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
