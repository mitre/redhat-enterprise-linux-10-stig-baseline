control 'SV-281348' do
  title 'RHEL 10 must use a reverse-path filter for Internet Protocol version 4 (IPv4) network traffic when possible by default.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface on which they were received. It must not be used on systems that are routers for complicated networks but is helpful for end hosts and routers serving small networks.

'
  desc 'check', 'Verify RHEL 10 uses reverse path filtering on IPv4 interfaces.

Check the value of the "net.ipv4.conf.default.rp_filter" with the following command:

$ sudo sysctl net.ipv4.conf.default.rp_filter
net.ipv4.conf.default.rp_filter = 1

If the returned line does not have a value of "1", or a line is not returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use reverse path filtering on IPv4 interfaces by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_rp_filter.conf

Add the following line to the file:

net.ipv4.conf.default.rp_filter = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85909r1167192_chk'
  tag severity: 'medium'
  tag gid: 'V-281348'
  tag rid: 'SV-281348r1167194_rule'
  tag stig_id: 'RHEL-10-800160'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85814r1167193_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00079']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001103']
  tag nist: ['SC-5 a', 'SC-7 (4) (b)']
end
