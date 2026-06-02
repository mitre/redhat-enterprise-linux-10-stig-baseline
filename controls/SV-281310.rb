control 'SV-281310' do
  title 'RHEL 10 must enable kernel parameters to enforce discretionary access control (DAC) on symlinks.'
  desc %q(By enabling the "fs.protected_symlinks" kernel parameter, symbolic links are permitted to be followed only when outside a sticky world-writable directory, or when the user identifier (UID) of the link and follower match, or when the directory owner matches the symlink's owner. Disallowing such symlinks helps mitigate vulnerabilities based on insecure file systems accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().

)
  desc 'check', 'Verify RHEL 10 is configured to enable DAC on symlinks.

Check the status of the "fs.protected_symlinks" kernel parameter with the following command:

$ sudo sysctl fs.protected_symlinks
fs.protected_symlinks = 1

If "fs.protected_symlinks" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enable DAC on symlinks with the following:

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-fs_protected_symlinks.conf

Add the following to the file:

fs.protected_symlinks = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85871r1167078_chk'
  tag severity: 'medium'
  tag gid: 'V-281310'
  tag rid: 'SV-281310r1167080_rule'
  tag stig_id: 'RHEL-10-701080'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag fix_id: 'F-85776r1167079_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end
