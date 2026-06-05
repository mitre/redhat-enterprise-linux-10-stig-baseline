control 'SV-281220' do
  title 'RHEL 10 must be configured so that password-auth uses a sufficient number of hashing rounds.'
  desc 'Passwords must be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords that are encrypted with a weak algorithm are no more protected than if they are kept in plain text.

Using more hashing rounds makes password cracking attacks more difficult.

'
  desc 'check', 'Verify RHEL 10 is configured to use a sufficient number of rounds for password hashing with the following command:

$ sudo grep rounds /etc/pam.d/password-auth
password sufficient pam_unix.so sha512 rounds=100000

If the setting is not configured or "rounds" is less than "100000", this a finding.'
  desc 'fix', 'Configure RHEL 10 to use "100000" hashing rounds for hashing passwords.

Add or modify the following line in "/etc/pam.d/password-auth" and set "rounds" to "100000":

password sufficient pam_unix.so sha512 rounds=100000'
  impact 0.5
  tag check_id: 'C-85781r1166610_chk'
  tag severity: 'medium'
  tag gid: 'V-281220'
  tag rid: 'SV-281220r1166612_rule'
  tag stig_id: 'RHEL-10-600720'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-85686r1166611_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-004062', 'CCI-000803']
  tag nist: ['IA-5 (1) (d)', 'IA-7']

  expected_line = 'password sufficient pam_unix.so sha512'
  pam_auth_files = input('pam_auth_files')
  password_hash_rounds = input('password_hash_rounds')

  describe pam(pam_auth_files['password-auth']) do
    its('lines') { should match_pam_rule(expected_line).any_with_integer_arg('rounds', '>=', password_hash_rounds) }
  end
end
