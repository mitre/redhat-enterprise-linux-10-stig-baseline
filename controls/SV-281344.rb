control 'SV-281344' do
  title 'RHEL 10 must log Internet Protocol version 4 (IPv4) packets with impossible addresses by default.'
  desc 'The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects, could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.

'
  desc 'check', 'Verify RHEL 10 logs IPv4 martian packets by default.

Check the value of the "net.ipv4.conf.default.log_martians" variable with the following command:

$ sudo sysctl net.ipv4.conf.default.log_martians
net.ipv4.conf.default.log_martians = 1

If "net.ipv4.conf.default.log_martians" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to log martian packets on IPv4 interfaces by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-ipv4_log_martians.conf

Add the following line to the file:

net.ipv4.conf.default.log_martians=1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85905r1167180_chk'
  tag severity: 'medium'
  tag gid: 'V-281344'
  tag rid: 'SV-281344r1167182_rule'
  tag stig_id: 'RHEL-10-800120'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85810r1167181_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00075']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001099']
  tag nist: ['SC-5 a', 'SC-7 (1)']
end
