control 'SV-281361' do
  title 'RHEL 10 must protect against or limit the effects of denial-of-service (DoS) attacks by ensuring that rate-limiting measures on impacted network interfaces are implemented.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of RHEL 10 to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Verify RHEL 10 protects against or limits the effects of DoS attacks by ensuring rate-limiting measures on impacted network interfaces are implemented.

Check that "nftables" is configured to allow rate limits on any connection to the system with the following command:

$ sudo grep -i firewallbackend /etc/firewalld/firewalld.conf
# FirewallBackend
FirewallBackend=nftables

If "nftables" is not set to "FirewallBackend", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that "nftables" is the default "firewallbackend" for "firewalld" by adding or editing the following line in "/etc/firewalld/firewalld.conf":

FirewallBackend=nftables

Establish rate-limiting rules based on organization-defined types of DoS attacks on impacted network interfaces.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-281361'
  tag rid: 'SV-281361r1167233_rule'
  tag stig_id: 'RHEL-10-800290'
  tag fix_id: 'F-85827r1167232_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5', 'SC-5 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe parse_config_file('/etc/firewalld/firewalld.conf') do
    its('FirewallBackend') { should eq 'nftables' }
  end
end
