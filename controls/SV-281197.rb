control 'SV-281197' do
  title 'RHEL 10 must maintain an account lock until the locked account is released by an administrator.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', %q(Verify RHEL 10 is configured to lock an account after three unsuccessful login attempts until released by an administrator with the following command:

$ sudo grep 'unlock_time =' /etc/security/faillock.conf
unlock_time = 0

If the "unlock_time" option is not set to "0", or the line is missing or commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to lock an account after three unsuccessful login attempts until released by an administrator with the following command:

$ authselect enable-feature with-faillock

Edit the "/etc/security/faillock.conf" file as follows:

unlock_time = 0'
  impact 0.5
  tag check_id: 'C-85758r1166541_chk'
  tag severity: 'medium'
  tag gid: 'V-281197'
  tag rid: 'SV-281197r1166543_rule'
  tag stig_id: 'RHEL-10-600425'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-85663r1166542_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'
  tag 'container'

  lockout_time = input('lockout_time')

  describe parse_config_file('/etc/security/faillock.conf') do
    its('unlock_time') { should cmp lockout_time }
  end
end
