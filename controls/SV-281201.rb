control 'SV-281201' do
  title 'RHEL 10 must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', "Verify RHEL 10 prohibits null or blank passwords with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding."
  desc 'fix', 'Configure RHEL 10 so that all accounts have a password, or lock the account with the following commands:

Perform a password reset:

$ sudo passwd [username]

To lock an account:

$ sudo passwd -l [username]'
  impact 0.5
  tag check_id: 'C-85762r1166553_chk'
  tag severity: 'medium'
  tag gid: 'V-281201'
  tag rid: 'SV-281201r1166555_rule'
  tag stig_id: 'RHEL-10-600460'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-85667r1166554_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-004066']
  tag nist: ['CM-6 b', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  users_with_blank_passwords = shadow.where { password.nil? || password.empty? }.users - input('users_allowed_blank_passwords')

  describe 'All users' do
    it 'should have a password set' do
      fail_msg = "Users with blank passwords:\n\t- #{users_with_blank_passwords.join("\n\t- ")}"
      expect(users_with_blank_passwords).to be_empty, fail_msg
    end
  end
end
