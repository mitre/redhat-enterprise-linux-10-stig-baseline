control 'SV-281340' do
  title 'RHEL 10 must be configured to use Transmission Control Protocol (TCP) syncookies.'
  desc 'Denial of service (DoS) is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.

'
  desc 'check', 'Verify RHEL 10 is configured to use Internet Protocol version 4 (IPv4) TCP syncookies.

Check the value of all "net.ipv4.tcp_syncookies" variables with the following command:

$ sudo sysctl net.ipv4.tcp_syncookies
net.ipv4.tcp_syncookies = 1

If the network parameter "ipv4.tcp_syncookies" is not equal to "1", or nothing is returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use TCP syncookies.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-ipv4_tcp_syncookies.conf

Add the following line to the file:

net.ipv4.tcp_syncookies = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85901r1167168_chk'
  tag severity: 'medium'
  tag gid: 'V-281340'
  tag rid: 'SV-281340r1167170_rule'
  tag stig_id: 'RHEL-10-800080'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85806r1167169_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00071']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001095']
  tag nist: ['SC-5 a', 'SC-5 (2)']
end
