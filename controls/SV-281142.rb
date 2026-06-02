control 'SV-281142' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the "sudoedit" command.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each system call made by all programs on the system. Therefore, it is very important to use system call rules only when absolutely necessary because these affect performance. More rules lead to poorer performance. The performance can be helped, however, by combining system calls into one rule whenever possible.

'
  desc 'check', 'Verify RHEL 10 is configured to audit the execution of the "sudoedit" command with the following command:

$ sudo auditctl -l | grep /usr/bin/sudoedit
-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1 -F key=priv_cmd

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to generate audit records upon successful and unsuccessful attempts to use the "sudoedit" command by adding or updating the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85703r1166376_chk'
  tag severity: 'medium'
  tag gid: 'V-281142'
  tag rid: 'SV-281142r1197231_rule'
  tag stig_id: 'RHEL-10-500560'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-85608r1166377_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000755-GPOS-00220']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-002884', 'CCI-000172', 'CCI-004188']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'MA-4 (1) (a)', 'AU-12 c', 'MA-3 (5)']
end
