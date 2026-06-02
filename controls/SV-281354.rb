control 'SV-281354' do
  title 'RHEL 10 must not accept router advertisements on all Internet Protocol version 6 (IPv6) interfaces.'
  desc 'An illicit router advertisement message could result in a man-in-the-middle attack.

'
  desc 'check', 'Note: If IPv6 is disabled on the system, this requirement is not applicable.

Verify RHEL 10 does not accept router advertisements on all IPv6 interfaces, unless the system is a router.

Check that "net.ipv6.conf.all.accept_ra" is set to not accept router advertisements by using the following command:

$ sudo sysctl net.ipv6.conf.all.accept_ra
net.ipv6.conf.all.accept_ra = 0

If "net.ipv6.conf.all.accept_ra" is not set to "0" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not accept router advertisements on all IPv6 interfaces, unless the system is a router.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_accept_ra.conf

Add the following line to the file:

net.ipv6.conf.all.accept_ra = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85915r1167210_chk'
  tag severity: 'medium'
  tag gid: 'V-281354'
  tag rid: 'SV-281354r1167212_rule'
  tag stig_id: 'RHEL-10-800220'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85820r1167211_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00085']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001109']
  tag nist: ['SC-5 a', 'SC-7 (5)']
end
