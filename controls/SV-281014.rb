control 'SV-281014' do
  title 'RHEL 10 must use FIPS 140-3-approved cryptographic algorithms for IP tunnels.'
  desc 'Overriding the systemwide cryptographic policy makes the behavior of the Libreswan service violate expectations and makes system configuration more fragmented.'
  desc 'check', 'Note: If the IPsec service is not installed, this requirement is not applicable.

Verify RHEL 10 sets the IPsec service to use the systemwide cryptographic policy with the following command:

$ sudo grep include /etc/ipsec.conf /etc/ipsec.d/*.conf
/etc/ipsec.conf:include /etc/crypto-policies/back-ends/libreswan.config

If the ipsec configuration file does not contain "include /etc/crypto-policies/back-ends/libreswan.config", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that Libreswan uses the systemwide cryptographic policy.

Add the following line to "/etc/ipsec.conf":

include /etc/crypto-policies/back-ends/libreswan.config'
  impact 0.7
  tag check_id: 'C-85575r1165395_chk'
  tag severity: 'high'
  tag gid: 'V-281014'
  tag rid: 'SV-281014r1165397_rule'
  tag stig_id: 'RHEL-10-300070'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-85480r1165396_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  expected_value = input('approved_crypto_backend')

  setting_check = command('grep include /etc/ipsec.conf /etc/ipsec.d/*.conf').stdout.strip.match?(/^.*:?[^#]include\s*#{expected_value}$/)

  describe 'RHEL 10 IPsec config' do
    it "should include the conf file '#{expected_value}'" do
      expect(setting_check).to eq(true), "Conf file '#{expected_value}' not included in ipsec config"
    end
  end
end
