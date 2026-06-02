control 'SV-281353' do
  title 'RHEL 10 must not enable Internet Protocol version 4 (IPv4) packet forwarding unless the system is a router.'
  desc 'Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this capability is used when not required, system network information may be transmitted unnecessarily across the network.

'
  desc 'check', 'Verify RHEL 10 is not performing IPv4 packet forwarding unless the system is a router.

Check that "net.ipv4.conf.all.forwarding" is disabled using the following command:

$ sudo sysctl net.ipv4.conf.all.forwarding
net.ipv4.conf.all.forwarding = 0

If "net.ipv4.conf.all.forwarding" is not set to "0" and is not documented with the information system security officer as an operational requirement or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not allow IPv4 packet forwarding unless the system is a router.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_forwarding.conf

Add the following line to the file:

net.ipv4.conf.all.forwarding = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85914r1167207_chk'
  tag severity: 'medium'
  tag gid: 'V-281353'
  tag rid: 'SV-281353r1167209_rule'
  tag stig_id: 'RHEL-10-800210'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85819r1167208_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00084']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001108']
  tag nist: ['SC-5 a', 'SC-7 (4) (e)']
end
