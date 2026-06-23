control 'SV-281019' do
  title 'RHEL 10 must be configured so that the "/etc/group-" file is owned by "root".'
  desc 'The "/etc/group-" file is a backup file of "/etc/group", and as such contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/group-" file is owned by "root" with the following command:

$ sudo stat -c "%U %n" /etc/group-
root /etc/group-

If the "/etc/group-" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the owner of the "/etc/group-" file is set to "root" by running the following command:

$ sudo chown root /etc/group-'
  impact 0.5
  tag check_id: 'C-85580r1165410_chk'
  tag severity: 'medium'
  tag gid: 'V-281019'
  tag rid: 'SV-281019r1165412_rule'
  tag stig_id: 'RHEL-10-400010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85485r1165411_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  describe file('/etc/group-') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
