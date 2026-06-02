control 'SV-281170' do
  title 'RHEL 10 must, for user account passwords, have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords must be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', %q(Verify RHEL 10 enforces a 60-day maximum time period for existing user account passwords with the following commands:

$ sudo awk -F: '$5 > 60 {print $1 "" "" $5}' /etc/shadow

$ sudo awk -F: '$5 <= 0 {print $1 "" "" $5}' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to enforce a 60-day maximum password lifetime restriction on user account passwords.

Set the 60-day maximum password lifetime restriction with the following command:

$ sudo passwd -x 60 [user]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-281170'
  tag rid: 'SV-281170r1184651_rule'
  tag stig_id: 'RHEL-10-600110'
  tag fix_id: 'F-85636r1166461_fix'
  tag cci: ['CCI-000199', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  value = input('pass_max_days')

  bad_users = users.where { uid >= 1000 }.where { value > 60 or maxdays.negative? }.usernames
  in_scope_users = bad_users - input('exempt_home_users')

  describe 'Users are not be able' do
    it "to retain passwords for more then #{value} day(s)" do
      failure_message = "The following users can update their password more then every #{value} day(s): #{in_scope_users.join(', ')}"
      expect(in_scope_users).to be_empty, failure_message
    end
  end
end
