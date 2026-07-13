control 'SV-281192' do
  title 'RHEL 10 must allow only the root account to have unrestricted access to the system.'
  desc 'An account has root authority if it has a user identifier (UID) of "0". Multiple accounts with a UID of "0" afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner.'
  desc 'check', %q(Verify RHEL 10 is configured so that only the "root" account has a UID "0" assignment with the following command:

$ awk -F: '$3 == 0 {print $1}' /etc/passwd
root

If any accounts other than "root" have a UID of "0", this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that only the "root" account has a UID assignment of "0".

Change the UID of any account on the system, other than "root", that has a UID of "0".

If the account is associated with system commands or applications, the UID should be changed to one greater than "0" but less than "1000". Otherwise, assign a UID of greater than "1000" that has not already been assigned.'
  impact 0.5
  tag check_id: 'C-85753r1166526_chk'
  tag severity: 'medium'
  tag gid: 'V-281192'
  tag rid: 'SV-281192r1166528_rule'
  tag stig_id: 'RHEL-10-600400'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85658r1166527_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  describe passwd.uids(0) do
    its('users') { should cmp 'root' }
    its('entries.length') { should eq 1 }
  end
end
