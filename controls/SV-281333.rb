control 'SV-281333' do
  title 'RHEL 10 must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary ports, protocols, and services on information systems.'
  desc 'check', 'Verify RHEL 10 is configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments.

Inspect the firewall configuration and running services to verify they are configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.

Check which services are currently active with the following command:

$ sudo firewall-cmd --list-all-zones

Ask the system administrator for the site or program PPSM Component Local Service Assessment (CLSA). Verify the services allowed by the firewall match the PPSM CLSA.

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM CAL, this is a finding.'
  desc 'fix', "Configure RHEL 10 to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the PPSM CAL and vulnerability assessments.

Update the host's firewall settings and/or running services to comply with the PPSM CLSA for the site or program and the PPSM CAL.

Run the following command to load the newly created rule(s):

$ sudo firewall-cmd --reload"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-281333'
  tag rid: 'SV-281333r1167149_rule'
  tag stig_id: 'RHEL-10-800010'
  tag fix_id: 'F-85799r1167148_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  firewalld_properties = input('firewalld_properties')

  describe firewalld do
    it { should be_running }
  end
  describe firewalld do
    its('ports') { should cmp [firewalld_properties['ports']] }
    its('protocols') { should cmp [firewalld_properties['protocols']] }
    its('services') { should cmp [firewalld_properties['services']] }
  end
end
