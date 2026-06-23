control 'SV-281121' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the "chcon" command.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each system call made by all programs on the system. Therefore, it is very important to use system call rules only when absolutely necessary because these affect performance. More rules lead to poorer performance. The performance can be helped, however, by combining system calls into one rule whenever possible.

'
  desc 'check', 'Verify RHEL 10 is configured to audit the execution of the "chcon" command with the following command:

$ sudo auditctl -l | grep chcon
-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_mod

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to generate audit records upon successful and unsuccessful attempts to use the "chcon" command by adding or updating the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85682r1166313_chk'
  tag severity: 'medium'
  tag gid: 'V-281121'
  tag rid: 'SV-281121r1166315_rule'
  tag stig_id: 'RHEL-10-500350'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-85587r1166314_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000468-GPOS-00212', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000463-GPOS-00207', 'SRG-OS-000465-GPOS-00209']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-002884', 'CCI-000172']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'MA-4 (1) (a)', 'AU-12 c']
  tag 'host'

  audit_command = '/usr/bin/chcon'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe 'Command' do
    it "#{audit_command} is audited properly" do
      audit_rule = auditd.file(audit_command)
      expect(audit_rule).to exist
      expect(audit_rule.action.uniq).to cmp 'always'
      expect(audit_rule.list.uniq).to cmp 'exit'
      expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
      expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
      auditctl_output = command("sudo auditctl -l | grep #{audit_command}").stdout.strip
      expect(auditctl_output).to match(/-S\s+all\b/)
    end
  end
end
