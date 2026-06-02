control 'SV-281204' do
  title 'RHEL 10 must ensure the password complexity module in the system-auth file is configured for three or fewer retries.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

RHEL 10 uses "pwquality" as a mechanism to enforce password complexity. This is set in both of the following: 

"/etc/pam.d/password-auth"
"/etc/pam.d/system-auth"

By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.'
  desc 'check', 'Verify RHEL 10 is configured to limit the "pwquality" retry option to "3" with the following command:

$ sudo grep -w retry /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 
retry = 3 

If the value of "retry" is set to "0" or greater than "3", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to limit the "pwquality" retry option to "3".

Add or update the following line in the "/etc/security/pwquality.conf" file or a file in the "/etc/security/pwquality.conf.d/" directory to contain the "retry" parameter:

retry = 3'
  impact 0.5
  tag check_id: 'C-85765r1166562_chk'
  tag severity: 'medium'
  tag gid: 'V-281204'
  tag rid: 'SV-281204r1197240_rule'
  tag stig_id: 'RHEL-10-600485'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-85670r1166563_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000192', 'CCI-004066']
  tag nist: ['CM-6 b', 'IA-5 (1) (a)', 'IA-5 (1) (h)']
  tag 'host'

  only_if('This control is Not Applicable for containers', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  describe 'System pwquality setting' do
    subject { parse_config(command('grep -rh retry /etc/security/pwquality.conf*').stdout.strip) }
    its('retry') { should cmp >= input('min_retry') }
  end
end
