control 'SV-281356' do
  title 'RHEL 10 must not forward Internet Protocol version 6 (IPv6) source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

'
  desc 'check', 'Note: If IPv6 is disabled on the system, this requirement is not applicable.

Verify RHEL 10 does not accept IPv6 source-routed packets.

Check the value of the "net.ipv6.conf.all.accept_source_route" variable with the following command:

$ sudo sysctl net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route = 0

If "net.ipv6.conf.all.accept_source_route" is not set to "0" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not accept IPv6 source-routed packets.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv6_accept_source_route.conf

Add the following line to the file:

net.ipv6.conf.all.accept_source_route = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85917r1167216_chk'
  tag severity: 'medium'
  tag gid: 'V-281356'
  tag rid: 'SV-281356r1167218_rule'
  tag stig_id: 'RHEL-10-800240'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85822r1167217_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00087']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001111']
  tag nist: ['SC-5 a', 'SC-7 (7)']
end
