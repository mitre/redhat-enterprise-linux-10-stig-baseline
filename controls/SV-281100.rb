control 'SV-281100' do
  title 'RHEL 10 must log username information when unsuccessful login attempts occur.'
  desc 'Without auditing of these events, it may be harder or impossible to identify what an attacker did after an attack.'
  desc 'check', 'Verify RHEL 10 "/etc/security/faillock.conf" is configured to log username information when unsuccessful login attempts occur with the following command:

$ sudo grep audit /etc/security/faillock.conf
audit

If the "audit" option is not set, is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to log username information when unsuccessful login attempts occur.

Enable the feature using the following command:

$ sudo authselect enable-feature with-faillock

Add/modify the "/etc/security/faillock.conf" file to match the following line:

audit'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-281100'
  tag rid: 'SV-281100r1165655_rule'
  tag stig_id: 'RHEL-10-500020'
  tag fix_id: 'F-85566r1165654_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/security/faillock.conf') do
    its('audit') { should_not be_nil }
  end
end
