control 'SV-281196' do
  title 'RHEL 10 must automatically lock an account when three unsuccessful login attempts occur during a 15-minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify RHEL 10 locks an account after three unsuccessful login attempts within a period of 15 minutes with the following command:

$ sudo grep fail_interval /etc/security/faillock.conf
fail_interval = 900

If the "fail_interval" option is not set to "900" or less (but not "0"), the line is commented out, or the line is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to lock out the "root" account after a number of incorrect login attempts within 15 minutes using "pam_faillock.so". 

Enable the feature using the following command:

$ authselect enable-feature with-faillock

Edit the "/etc/security/faillock.conf" file as follows:

fail_interval = 900'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-281196'
  tag rid: 'SV-281196r1166540_rule'
  tag stig_id: 'RHEL-10-600420'
  tag fix_id: 'F-85662r1166539_fix'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'
  tag 'container'

  if input('centralized_account_mgmt')
    impact 0.0
    describe 'N/A' do
      skip 'The system is using a centralized account mangement method; this control is Not Applicable'
    end
  else
    describe parse_config_file(input('security_faillock_conf')) do
      its('fail_interval') { should cmp >= input('fail_interval') }
    end
  end
end
