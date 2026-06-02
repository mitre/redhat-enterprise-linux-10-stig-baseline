control 'SV-281045' do
  title 'RHEL 10 must be configured so that world-writable directories are owned by root, sys, bin, or an application user.'
  desc 'If a world-writable directory is not owned by root, sys, bin, or an application user identifier (UID), unauthorized users may be able to modify files created by others.

The only authorized public directories are temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.'
  desc 'check', 'Verify RHEL 10 world-writable directories are owned by root, a system account, or an application account with the following command:

$ sudo find / -xdev -type d -perm -0002 -uid +999 -exec stat -c "%U, %u, %A, %n" {} \\; 2>/dev/null

If output indicates that world-writable directories are owned by any account other than root or an approved system account, this is a finding.'
  desc 'fix', 'Configure RHEL 10 public directories to be owned by root or a system account to prevent unauthorized and unintended information transferred via shared system resources.

Use the following command template to set ownership of public directories to root or a system account:

$ sudo chown [root or system account] [Public Directory]'
  impact 0.5
  tag check_id: 'C-85606r1165488_chk'
  tag severity: 'medium'
  tag gid: 'V-281045'
  tag rid: 'SV-281045r1165490_rule'
  tag stig_id: 'RHEL-10-400140'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-85511r1165489_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
