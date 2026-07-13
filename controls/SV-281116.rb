control 'SV-281116' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the "execve" system call.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. 

Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

'
  desc 'check', 'Verify RHEL 10 is configured to audit the execution of the "execve" system call with the following command:

$ sudo auditctl -l | grep execve
-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv

If the command does not return all lines, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to generate audit records upon successful and unsuccessful attempts to use the "execve" system call.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85677r1166298_chk'
  tag severity: 'medium'
  tag gid: 'V-281116'
  tag rid: 'SV-281116r1166300_rule'
  tag stig_id: 'RHEL-10-500300'
  tag gtitle: 'SRG-OS-000326-GPOS-00126'
  tag fix_id: 'F-85582r1166299_fix'
  tag satisfies: ['SRG-OS-000326-GPOS-00126', 'SRG-OS-000327-GPOS-00127', 'SRG-OS-000755-GPOS-00220']
  tag 'documentable'
  tag cci: ['CCI-002233', 'CCI-002234', 'CCI-004188']
  tag nist: ['AC-6 (8)', 'AC-6 (9)', 'MA-3 (5)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_syscalls = ['execve']

  describe 'Syscall' do
    audit_syscalls.each do |audit_syscall|
      it "#{audit_syscall} is audited properly" do
        audit_rule = auditd.syscall(audit_syscall)
        expect(audit_rule).to exist
        expect(audit_rule.action.uniq).to cmp 'always'
        expect(audit_rule.list.uniq).to cmp 'exit'
        if os.arch.match(/64/)
          expect(audit_rule.arch.uniq).to include('b32', 'b64')
        else
          expect(audit_rule.arch.uniq).to cmp 'b32'
        end
        expect(audit_rule.fields.flatten).to include('uid!=euid', 'gid!=egid', 'euid=0', 'egid=0')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_syscall])
      end
    end
  end
end
