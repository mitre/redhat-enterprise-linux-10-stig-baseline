control 'SV-281024' do
  title 'RHEL 10 must be configured so that the "/etc/gshadow-" file is group-owned by "root".'
  desc 'The "/etc/gshadow-" file is a backup of "/etc/gshadow", and as such contains group password hashes. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/gshadow-" file is group-owned by "root" with the following command:

$ sudo stat -c "%G %n" /etc/gshadow-
root /etc/gshadow-

If the "/etc/gshadow-" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the group of the "/etc/gshadow-" file is set to "root" by running the following command:

$ sudo chgrp root /etc/gshadow-'
  impact 0.5
  tag check_id: 'C-85585r1165425_chk'
  tag severity: 'medium'
  tag gid: 'V-281024'
  tag rid: 'SV-281024r1165427_rule'
  tag stig_id: 'RHEL-10-400035'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85490r1165426_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
