control 'SV-281198' do
  title 'RHEL 10 must ensure account lockouts persist.'
  desc 'Having lockouts persist across reboots ensures that an account is unlocked only by an administrator. If the lockouts did not persist across reboots, an attacker could reboot the system to continue brute force attacks against the accounts on the system.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/security/faillock.conf" file uses a nondefault "faillock" directory to ensure contents persist after reboot with the following command:

$ sudo grep -w dir /etc/security/faillock.conf
dir = /var/log/faillock

If the "dir" option is not set to a nondefault documented tally log directory, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to maintain the contents of the "faillock" directory after a reboot.

Add/modify the "/etc/security/faillock.conf" file to match the following line:

dir = /var/log/faillock'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-281198'
  tag rid: 'SV-281198r1166546_rule'
  tag stig_id: 'RHEL-10-600430'
  tag fix_id: 'F-85664r1166545_fix'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/faillock.conf') do
    its('dir') { should cmp input('log_directory') }
  end
end
