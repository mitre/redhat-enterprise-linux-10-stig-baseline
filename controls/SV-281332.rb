control 'SV-281332' do
  title 'RHEL 10 must control remote access methods.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business.

'
  desc 'check', 'Verify RHEL 10 controls remote access methods by inspecting the firewall configuration.

Inspect the list of enabled firewall ports and verify they are configured correctly by running the following command:

$ sudo firewall-cmd --list-all

Ask the system administrator for the site or program Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA). Verify the services allowed by the firewall match the PPSM CLSA.

If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), or there are no firewall rules configured, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to allow approved settings and/or running services to comply with the PPSM CLSA for the site or program and the PPSM CAL.

To open a port for a service, configure "firewalld" using the following command:

$ sudo firewall-cmd --permanent --add-port=port_number/tcp
or
$ sudo firewall-cmd --permanent --add-service=service_name'
  impact 0.5
  tag check_id: 'C-85893r1167144_chk'
  tag severity: 'medium'
  tag gid: 'V-281332'
  tag rid: 'SV-281332r1167146_rule'
  tag stig_id: 'RHEL-10-800000'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-85798r1167145_fix'
  tag satisfies: ['SRG-OS-000096-GPOS-00050', 'SRG-OS-000297-GPOS-00115']
  tag 'documentable'
  tag cci: ['CCI-000382', 'CCI-002314']
  tag nist: ['CM-7 b', 'AC-17 (1)']

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
