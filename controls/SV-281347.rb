control 'SV-281347' do
  title 'RHEL 10 must not forward Internet Protocol version 4 (IPv4) source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.

Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It must be disabled unless it is absolutely required, such as when IPv4 forwarding is enabled and the system is legitimately functioning as a router.

'
  desc 'check', 'Verify RHEL 10 does not accept IPv4 source-routed packets by default.

Check the value of the "net.ipv4.conf.default.accept_source_route" variable with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_source_route
net.ipv4.conf.default.accept_source_route = 0

If "net.ipv4.conf.default.accept_source_route" is not set to "0" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not forward IPv4 source-routed packets by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-ipv4_accept_source_route.conf

Add the following line to the file:

net.ipv4.conf.default.accept_source_route = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85908r1167189_chk'
  tag severity: 'medium'
  tag gid: 'V-281347'
  tag rid: 'SV-281347r1167191_rule'
  tag stig_id: 'RHEL-10-800150'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85813r1167190_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00078']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001102']
  tag nist: ['SC-5 a', 'SC-7 (4) (a)']
end
