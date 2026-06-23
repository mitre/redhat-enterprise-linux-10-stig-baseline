control 'SV-281125' do
  title 'RHEL 10 must generate audit records for successful and unsuccessful uses of the "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" system calls.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

When a user logs on, the auid is set to the uid of the account that is being authenticated. Daemons are not user sessions and have the loginuid set to -1. The auid representation is an unsigned 32-bit integer, which equals 4294967295. The audit system interprets -1, 4294967295, and "unset" in the same way.

The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary because these affect performance. More rules lead to poorer performance. The performance can be helped, however, by combining syscalls into one rule whenever possible.

'
  desc 'check', %q(Verify RHEL 10 is configured to audit successful/unsuccessful attempts to use the "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" system calls with the following command:

$ sudo auditctl -l | grep 'open\|truncate\|creat'
-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access

If the output does not produce rules containing "-F exit=-EPERM", this is a finding.

If the output does not produce rules containing "-F exit=-EACCES", this is a finding.

If the command does not return an audit rule for "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at", or any of the lines returned are commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to generate audit records upon successful and unsuccessful use of the "truncate", "ftruncate", "creat", "open", "openat", and "open_by_handle_at" system calls by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=unset -k perm_access

-a always,exit -F arch=b32 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access
-a always,exit -F arch=b64 -S truncate,ftruncate,creat,open,openat,open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=unset -k perm_access

Restart the audit daemon with the following command for the changes to take effect:

$ sudo service auditd restart'
  impact 0.5
  tag check_id: 'C-85686r1166325_chk'
  tag severity: 'medium'
  tag gid: 'V-281125'
  tag rid: 'SV-281125r1197225_rule'
  tag stig_id: 'RHEL-10-500390'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-85591r1166326_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000458-GPOS-00203', 'SRG-OS-000461-GPOS-00205']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-002884', 'CCI-000172']
  tag nist: ['AU-3 a', 'AU-3 (1)', 'AU-12 a', 'MA-4 (1) (a)', 'AU-12 c']
  tag 'host'

  audit_syscalls = ['truncate', 'ftruncate', 'creat', 'open', 'openat', 'open_by_handle_at']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

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
        expect(audit_rule.fields.flatten).to include('auid>=1000', 'auid!=-1')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_syscall])
      end
    end
  end
end
