control 'SV-281199' do
  title 'RHEL 10 must not have unauthorized accounts.'
  desc 'Having lockouts persist across reboots ensures that account is unlocked only by an administrator. If the lockouts did not persist across reboots, an attacker could reboot the system to continue brute force attacks against the accounts on the system.'
  desc 'check', 'Verify RHEL 10 has no unauthorized local interactive user accounts with the following command:

$ less /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
nsauser:x:1000:1000:nsauser:/home/nsauser:/bin/bash
doduser:x:1001:1001:doduser:/home/doduser:/bin/bash

Interactive user accounts generally will have a user ID (UID) of 1000 or greater, a home directory in a specific partition, and an interactive shell.

Obtain the list of interactive user accounts authorized to be on the system from the system administrator or information system security officer and compare it to the list of local interactive user accounts on the system.

If there are unauthorized local user accounts on the system, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have no unauthorized local interactive user accounts with the following command, where <unauthorized_user> is the unauthorized account:

$ sudo userdel  <unauthorized_user>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-281199'
  tag rid: 'SV-281199r1166549_rule'
  tag stig_id: 'RHEL-10-600450'
  tag fix_id: 'F-85665r1166548_fix'
  tag cci: ['CCI-000366', 'CCI-000213']
  tag nist: ['CM-6 b', 'AC-3']
  tag 'host'
  tag 'container'

  failing_users = passwd.users.reject { |u| (input('known_system_accounts') + input('user_accounts')).uniq.include?(u) }

  describe 'All users' do
    it 'should have an explicit, authorized purpose (either a known user account or a required system account)' do
      expect(failing_users).to be_empty, "Failing users:\n\t- #{failing_users.join("\n\t- ")}"
    end
  end
end
