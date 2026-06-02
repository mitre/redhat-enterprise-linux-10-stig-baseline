control 'SV-280953' do
  title 'RHEL 10 must have the "nss-tools" package installed.'
  desc 'Network Security Services (NSS) is a set of libraries designed to support cross-platform development of security-enabled client and server applications. Install the "nss-tools" package to install command-line tools to manipulate the NSS certificate and key database.'
  desc 'check', 'Verify RHEL 10 has the "nss-tools" package installed with the following command:

$ sudo dnf list --installed nss-tools
Installed Packages
nss-tools.x86_64                           3.112.0-4.el10_0                           @rhel-10-for-x86_64-appstream-rpms

If the "nss-tools" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "nss-tools" package installed with the following command:

$ sudo dnf -y install nss-tools'
  impact 0.5
  tag check_id: 'C-85514r1195341_chk'
  tag severity: 'medium'
  tag gid: 'V-280953'
  tag rid: 'SV-280953r1195342_rule'
  tag stig_id: 'RHEL-10-200510'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85419r1165213_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'
  tag 'container'

  describe package('nss-tools') do
    it { should be_installed }
  end
end
