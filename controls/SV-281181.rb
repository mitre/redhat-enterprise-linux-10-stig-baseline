control 'SV-281181' do
  title 'RHEL 10 must enforce that passwords be created with a minimum of 15 characters.'
  desc 'The shorter the password, the lower the number of possible combinations that must be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to increase exponentially the time and/or resources required to compromise the password.

RHEL 10 uses "pwquality" as a mechanism to enforce password complexity. Configurations are set in the "etc/security/pwquality.conf" file.

The "minlen", sometimes noted as minimum length, acts as a "score" of complexity based on the credit components of the "pwquality" module. By setting the credit components to a negative value, those components will not only be required but will not count toward the total "score" of "minlen". This will enable "minlen" to require a 15-character minimum.

The DOD minimum password requirement is 15 characters.'
  desc 'check', 'Verify RHEL 10 enforces a minimum 15-character password length with the following command:

$ sudo grep -s minlen /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
/etc/security/pwquality.conf:minlen = 15

If the command does not return a "minlen" value of "15" or greater, does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enforce a minimum 15-character password length.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "minlen" parameter:

minlen = 15'
  impact 0.5
  tag check_id: 'C-85742r1195419_chk'
  tag severity: 'medium'
  tag gid: 'V-281181'
  tag rid: 'SV-281181r1195421_rule'
  tag stig_id: 'RHEL-10-600220'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-85647r1195420_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']
end
