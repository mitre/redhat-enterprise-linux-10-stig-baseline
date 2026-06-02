control 'SV-281331' do
  title 'RHEL 10 must prohibit the use of cached authenticators after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'Verify RHEL 10 System Security Services Daemon (SSSD) prohibits the use of cached authentications after one day with the following command:

Note: Cached authentication settings should be configured even if smart card authentication is not used on the system.

Determine if SSSD allows cached authentications with the following command:

$ sudo grep -irs cache_credentials /etc/sssd/sssd.conf /etc/sssd/conf.d/ | grep -v "^#"
cache_credentials = true

If "cache_credentials" is set to "false" or missing from the configuration file, this is not a finding and no further checks are required.

If "cache_credentials" is set to "true", check that SSSD prohibits the use of cached authentications after one day with the following command:

$ sudo grep -irs offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/ | grep -v "^#"
offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Configure RHEL 10 SSSD to prohibit the use of cached authentications after one day.

Edit the file "/etc/sssd/sssd.conf" or a configuration file in "/etc/sssd/conf.d" and add or edit the following line just below the line [pam]:

offline_credentials_expiration = 1

Restart the "sssd" service with the following command for the changes to take effect: 

$ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag gid: 'V-281331'
  tag rid: 'SV-281331r1167143_rule'
  tag stig_id: 'RHEL-10-701290'
  tag fix_id: 'F-85797r1167142_fix'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
  tag 'host'

  sssd_config = parse_config_file('/etc/sssd/sssd.conf')

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe.one do
    describe 'Cache credentials enabled' do
      subject { sssd_config.content }
      it { should_not match(/cache_credentials\s*=\s*true/) }
    end
    describe 'Offline credentials expiration' do
      subject { sssd_config }
      its('pam.offline_credentials_expiration') { should cmp '1' }
    end
  end
end
