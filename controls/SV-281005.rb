control 'SV-281005' do
  title 'RHEL 10 must have the "pkcs11-provider" package installed.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. The DOD common access card (CAC) with DOD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Verify RHEL 10 has the "openssl-pkcs11" package installed with the following command:

$ sudo dnf list --installed pkcs11-provider
Installed Packages
pkcs11-provider.x86_64                           1.0-3.el10_0                            @rhel-10-for-x86_64-baseos-rpms

If the "openssl-pkcs11" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "openssl-pkcs11" package installed with the following command:

$ sudo dnf -y install pkcs11-provider'
  impact 0.5
  tag check_id: 'C-85566r1195394_chk'
  tag severity: 'medium'
  tag gid: 'V-281005'
  tag rid: 'SV-281005r1195395_rule'
  tag stig_id: 'RHEL-10-200730'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-85471r1165369_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000375-GPOS-00160', 'SRG-OS-000377-GPOS-00162']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-004046', 'CCI-001954']
  tag nist: ['IA-2 (1)', 'IA-2 (6) (a)', 'IA-2 (12)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternate_mfa_method') == ''
    describe package('pkcs11-provider') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'N/A' do
      skip 'The system is using an approved alternative MFA method; this control is Not Applicable.'
    end
  end
end
