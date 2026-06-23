control 'SV-281094' do
  title 'RHEL 10 must enforce a mode of "0755" or less permissive for audit tools.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 10 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Verify RHEL 10 is configured so that the audit tools have a mode of "0755" or less with the following command:

$ stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/rsyslogd /sbin/augenrules
755 /sbin/auditctl
755 /sbin/aureport
755 /sbin/ausearch
755 /sbin/auditd
755 /sbin/rsyslogd
755 /sbin/augenrules

If any of the audit tool files have a mode more permissive than "0755", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the audit tools to have a mode of "0755" by running the following command:

$ sudo chmod 0755 [audit_tool]

Replace "[audit_tool]" with each audit tool that has a mode more permissive than "0755".'
  impact 0.5
  tag check_id: 'C-85655r1165635_chk'
  tag severity: 'medium'
  tag gid: 'V-281094'
  tag rid: 'SV-281094r1165637_rule'
  tag stig_id: 'RHEL-10-400450'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-85560r1165636_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_tools = input('audit_tools')

  failing_tools = audit_tools.select { |at| file(at).more_permissive_than?(input('audit_tool_mode')) }

  describe 'Audit executables' do
    it "should be no more permissive than '#{input('audit_tool_mode')}'" do
      expect(failing_tools).to be_empty, "Failing tools:\n\t- #{failing_tools.join("\n\t- ")}"
    end
  end
end
