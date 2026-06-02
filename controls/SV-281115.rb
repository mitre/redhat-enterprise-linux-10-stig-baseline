control 'SV-281115' do
  title 'RHEL 10 must log Secure Shell (SSH) connection attempts and failures to the server.'
  desc 'SSH provides several logging levels with varying amounts of verbosity. "DEBUG" is specifically not recommended other than strictly for debugging SSH communications because it provides so much data that it is difficult to identify important security information. "INFO" or "VERBOSE" level is the basic level that only records login activity of SSH users. In many situations, such as incident response, it is important to determine when a particular user was active on a system. The logout record can eliminate users who disconnected, which helps narrow the field.'
  desc 'check', %q(Verify RHEL 10 logs SSH connection attempts and failures to the server with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*loglevel'
/etc/ssh/sshd_config.d/90-sshd.conf:LogLevel VERBOSE

If a value of "VERBOSE" is not returned, or the line is commented out or missing, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to log connection attempts by adding or modifying the following line in "/etc/ssh/sshd_config" or in a file in "/etc/ssh/sshd_config.d":

LogLevel VERBOSE

Restart the SSH daemon with the following command for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85676r1166295_chk'
  tag severity: 'medium'
  tag gid: 'V-281115'
  tag rid: 'SV-281115r1184650_rule'
  tag stig_id: 'RHEL-10-500215'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-85581r1166296_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
