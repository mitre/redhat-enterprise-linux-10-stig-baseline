control 'SV-281078' do
  title 'RHEL 10 must be configured so that audit tools are group-owned by "root".'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data; therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

RHEL 10 systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools, and the corresponding rights the user enjoys, to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

'
  desc 'check', 'Verify RHEL 10 audit tools are group-owned by "root" with the following command:

$ sudo stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/auditd /sbin/rsyslogd /sbin/augenrules
root /sbin/auditctl
root /sbin/aureport
root /sbin/ausearch
root /sbin/auditd
root /sbin/rsyslogd
root /sbin/augenrules

If any audit tools do not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the audit tools are group-owned by "root" by running the following command:

$ sudo chgrp root [audit_tool]

Replace "[audit_tool]" with each audit tool not group-owned by "root".'
  impact 0.5
  tag check_id: 'C-85639r1165587_chk'
  tag severity: 'medium'
  tag gid: 'V-281078'
  tag rid: 'SV-281078r1165589_rule'
  tag stig_id: 'RHEL-10-400305'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-85544r1165588_fix'
  tag satisfies: ['SRG-OS-000256-GPOS-00097', 'SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 a', 'AU-9', 'AU-9']
end
