control 'SV-280972' do
  title 'RHEL 10 must have the "pcsc-lite" package installed.'
  desc 'The "pcsc-lite" package must be installed if it is to be available for multifactor authentication using smart cards.'
  desc 'check', 'Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Verify RHEL 10 has the "pcsc-lite" package installed with the following command:

$ sudo dnf list --installed pcsc-lite
Installed Packages
pcsc-lite.x86_64                                         2.2.3-2.el10                                          @anaconda

If the "pcsc-lite" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "pcsc-lite" package installed with the following command:

$ sudo dnf -y install pcsc-lite'
  impact 0.5
  tag check_id: 'C-85533r1195359_chk'
  tag severity: 'medium'
  tag gid: 'V-280972'
  tag rid: 'SV-280972r1195360_rule'
  tag stig_id: 'RHEL-10-200610'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85438r1165270_fix'
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-004046']
  tag nist: ['IA-2 (11)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('smart_card_enabled')
    describe package('pcsc-lite') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement; this control is Not Applicable.'
    end
  end
end
