control 'SV-280976' do
  title 'RHEL 10 must use the common access card (CAC) smart card driver.'
  desc 'Smart card login provides two-factor authentication stronger than that provided by a username and password combination. Smart cards leverage public key infrastructure to provide and verify credentials. Configuring the smart card driver helps to prevent the use of unauthorized smart cards.'
  desc 'check', 'Verify RHEL 10 loads the CAC driver with the following command:

$ sudo opensc-tool --get-conf-entry app:default:card_drivers
cac

If "cac" is not listed as a card driver, or no line is returned for "card_drivers", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to load the CAC driver:

$ sudo opensc-tool --set-conf-entry app:default:card_drivers:cac

Restart the pcscd service with the following command for the changes to take effect:

$ sudo systemctl restart pcscd'
  impact 0.5
  tag check_id: 'C-85537r1165281_chk'
  tag severity: 'medium'
  tag gid: 'V-280976'
  tag rid: 'SV-280976r1165283_rule'
  tag stig_id: 'RHEL-10-200621'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-85442r1165282_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000109-GPOS-00056', 'SRG-OS-000108-GPOS-00055', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-000770', 'CCI-001941', 'CCI-001942', 'CCI-000765', 'CCI-004045']
  tag nist: ['IA-2', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (5)', 'IA-2 (8)', 'IA-2 (9)', 'IA-2 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('smart_card_enabled')
    describe parse_config_file('/etc/opensc.conf') do
      its('card_drivers') { should cmp 'cac' }
    end
  else
    impact 0.0
    describe 'The system is not smartcard enabled thus this control is Not Applicable' do
      skip 'The system is not using Smartcards / PIVs to fulfil the MFA requirement; this control is Not Applicable.'
    end
  end
end
