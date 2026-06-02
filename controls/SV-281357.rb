control 'SV-281357' do
  title 'RHEL 10 must not enable Internet Protocol version 6 (IPv6) packet forwarding unless the system is a router.'
  desc 'IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.

'
  desc 'check', 'Note: If IPv6 is disabled on the system, this requirement is not applicable.

Verify RHEL 10 is not performing IPv6 packet forwarding unless the system is a router.

Check the value of the "net.ipv6.conf.all.forwarding" variable with the following command:

$ sudo sysctl net.ipv6.conf.all.forwarding
net.ipv6.conf.all.forwarding = 0

If "net.ipv6.conf.all.forwarding" is not set to "0" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not allow IPv6 packet forwarding unless the system is a router.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv6_forwarding.conf

Add the following line to the file:

net.ipv6.conf.all.forwarding = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85918r1167219_chk'
  tag severity: 'medium'
  tag gid: 'V-281357'
  tag rid: 'SV-281357r1167221_rule'
  tag stig_id: 'RHEL-10-800250'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85823r1167220_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00088']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001112']
  tag nist: ['SC-5 a', 'SC-7 (8)']
end
