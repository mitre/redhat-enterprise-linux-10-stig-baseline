control 'SV-281025' do
  title 'RHEL 10 must be configured so that the "/etc/passwd" file is owned by "root".'
  desc 'The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/passwd" file is owned by "root" with the following command:

$ sudo stat -c "%U %n" /etc/passwd
root /etc/passwd

If the "/etc/passwd" file does not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the owner of the "/etc/passwd" file is set to "root" by running the following command:

$ sudo chown root /etc/passwd'
  impact 0.5
  tag check_id: 'C-85586r1165428_chk'
  tag severity: 'medium'
  tag gid: 'V-281025'
  tag rid: 'SV-281025r1165430_rule'
  tag stig_id: 'RHEL-10-400040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85491r1165429_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe file('/etc/passwd') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
