control 'SV-281151' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the shutdown command.'
  desc 'Misuse of the shutdown command may cause availability issues for the system.'
  desc 'check', 'Verify RHEL 10 is configured to audit the execution of the "shutdown" command with the following command:

$ sudo cat /etc/audit/rules.d/* | grep shutdown
-a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to generate audit records upon successful and unsuccessful uses of the "shutdown" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85712r1166403_chk'
  tag severity: 'medium'
  tag gid: 'V-281151'
  tag rid: 'SV-281151r1166405_rule'
  tag stig_id: 'RHEL-10-500650'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-85617r1166404_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  audit_command = '/usr/sbin/shutdown'

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
