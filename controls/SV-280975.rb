control 'SV-280975' do
  title 'RHEL 10 must have the "opensc" package installed.'
  desc 'The use of Personal Identity Verification (PIV) credentials facilitates standardization and reduces the risk of unauthorized access.

The DOD has mandated the use of the common access card (CAC) to support identity management and personal authentication for systems covered under Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a primary component of layered protection for national security systems.'
  desc 'check', 'Verify RHEL 10 has the "opensc" package installed with the following command:

$ sudo dnf list --installed opensc
Installed Packages
opensc.x86_64                               0.26.1-1.el10                                @rhel-10-for-x86_64-baseos-rpm

If the "opensc" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "opensc" package installed with the following command:

$ sudo dnf -y install opensc'
  impact 0.5
  tag check_id: 'C-85536r1195363_chk'
  tag severity: 'medium'
  tag gid: 'V-280975'
  tag rid: 'SV-280975r1195364_rule'
  tag stig_id: 'RHEL-10-200620'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85441r1165279_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000376-GPOS-00161']
  tag 'documentable'
  tag cci: ['CCI-001948', 'CCI-001953', 'CCI-004046']
  tag nist: ['IA-2 (11)', 'IA-2 (12)', 'IA-2 (6) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('smart_card_enabled')
    describe package('opensc') do
      it { should be_installed }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement; this control is Not Applicable.'
    end
  end
end
