control 'SV-280973' do
  title 'RHEL 10 must have the "pcscd" service set to active.'
  desc 'The information system ensures that even if it is compromised, that compromise will not affect credentials stored on the authentication device.

The daemon program for "pcsc-lite" and the MuscleCard framework is "pcscd". It is a resource manager that coordinates communications with smart card readers, smart cards, and cryptographic tokens that are connected to the system.'
  desc 'check', 'Verify RHEL 10 has the "pcscd" socket set to active with the following command:

$ systemctl is-active pcscd.socket
active

If the "pcscd" socket is not active, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "pcscd" socket set to active with the following command:

$ sudo systemctl enable --now pcscd.socket'
  impact 0.5
  tag check_id: 'C-85534r1165272_chk'
  tag severity: 'medium'
  tag gid: 'V-280973'
  tag rid: 'SV-280973r1165274_rule'
  tag stig_id: 'RHEL-10-200611'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-85439r1165273_fix'
  tag 'documentable'
  tag cci: ['CCI-004046']
  tag nist: ['IA-2 (6) (a)']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('smart_card_enabled')
    describe service('pcscd') do
      it { should be_enabled }
      it { should be_running }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement; this control is Not Applicable.'
    end
  end
end
