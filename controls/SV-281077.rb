control 'SV-281077' do
  title 'RHEL 10 must be configured so that audit tools are owned by "root".'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 10 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Verify RHEL 10 audit tools are owned by "root" with the following command:

$ sudo stat -c "%U %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/rsyslogd /sbin/augenrules
root /sbin/auditctl
root /sbin/aureport
root /sbin/ausearch
root /sbin/auditd
root /sbin/rsyslogd
root /sbin/augenrules

If any audit tools do not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the audit tools are owned by "root" by running the following command:

$ sudo chown root [audit_tool]

Replace "[audit_tool]" with each audit tool not owned by "root".'
  impact 0.5
  tag check_id: 'C-85638r1165584_chk'
  tag severity: 'medium'
  tag gid: 'V-281077'
  tag rid: 'SV-281077r1165586_rule'
  tag stig_id: 'RHEL-10-400300'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-85543r1165585_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_tools = ['/sbin/auditctl', '/sbin/aureport', '/sbin/ausearch', '/sbin/autrace', '/sbin/auditd', '/sbin/rsyslogd', '/sbin/augenrules']

  failing_tools = audit_tools.reject { |at| file(at).owned_by?('root') }

  describe 'Audit executables' do
    it 'should be owned by root' do
      expect(failing_tools).to be_empty, "Failing tools:\n\t- #{failing_tools.join("\n\t- ")}"
    end
  end
end
