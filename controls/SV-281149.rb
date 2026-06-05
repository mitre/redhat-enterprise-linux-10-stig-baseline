control 'SV-281149' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the "poweroff" command.'
  desc 'Misuse of the "poweroff" command may cause availability issues for the system.'
  desc 'check', 'Verify RHEL 10 is configured to audit the execution of the "poweroff" command with the following command:

$ sudo auditctl -l | grep poweroff
-a always,exit -S all -F path=/usr/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-poweroff

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to generate audit records upon successful and unsuccessful uses of the "poweroff" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/poweroff -F perm=x -F auid>=1000 -F auid!=unset -k privileged-poweroff

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85710r1166397_chk'
  tag severity: 'medium'
  tag gid: 'V-281149'
  tag rid: 'SV-281149r1166399_rule'
  tag stig_id: 'RHEL-10-500630'
  tag gtitle: 'SRG-OS-000477-GPOS-00222'
  tag fix_id: 'F-85615r1166398_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  audit_command = '/usr/sbin/poweroff'

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
