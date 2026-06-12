control 'SV-280974' do
  title 'RHEL 10 must have the "pcsc-lite-ccid" package installed.'
  desc 'The "pcsc-lite-ccid" package must be installed if it is to be available for multifactor authentication using smart cards.'
  desc 'check', 'Verify RHEL 10 has the "pcsc-lite-ccid" package installed with the following command:

$ sudo dnf list --installed pcsc-lite-ccid
Installed Packages
pcsc-lite-ccid.x86_64                                       1.6.0-2.el10                                       @anaconda

If the "pcsc-lite-ccid" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "pcsc-lite-ccid" package installed with the following command:

$ sudo dnf -y install pcsc-lite-ccid'
  impact 0.5
  tag check_id: 'C-85535r1195361_chk'
  tag severity: 'medium'
  tag gid: 'V-280974'
  tag rid: 'SV-280974r1195362_rule'
  tag stig_id: 'RHEL-10-200612'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85440r1165276_fix'
  tag 'documentable'
  tag cci: ['CCI-004046']
  tag nist: ['IA-2 (6) (a)']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('smart_card_enabled')
    describe package('pcsc-lite-ccid') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement; this control is Not Applicable.'
    end
  end
end
