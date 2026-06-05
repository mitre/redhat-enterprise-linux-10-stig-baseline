control 'SV-281017' do
  title 'RHEL 10 must be configured so that the "/etc/group" file is owned by root.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that "/etc/group" file is owned by "root" with the following command:

$ sudo stat -c "%U %n" /etc/group
root /etc/group

If the "/etc/group" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the owner of the file "/etc/group" is set to "root" by running the following command:

$ sudo chown root /etc/group'
  impact 0.5
  tag check_id: 'C-85578r1165404_chk'
  tag severity: 'medium'
  tag gid: 'V-281017'
  tag rid: 'SV-281017r1165406_rule'
  tag stig_id: 'RHEL-10-400000'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85483r1165405_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe file('/etc/group') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
