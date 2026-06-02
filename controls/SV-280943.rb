control 'SV-280943' do
  title 'RHEL 10 must not have the "nfs-utils" package installed.'
  desc 'The "nfs-utils" package provides a daemon for the kernel Network File System (NFS) server and related tools. This package also contains the "showmount" program. The "showmount" program queries the mount daemon on a remote host for information about the NFS server on the remote host. For example, "showmount" can display the clients that are mounted on that host.'
  desc 'check', 'Verify RHEL 10 does not have the "nfs-utils" package installed with the following command:

$ sudo dnf list --installed nfs-utils
Error: No matching Packages to list

If the "nfs-utils" package is installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not have the "nfs-utils" package installed with the following command:

$ sudo dnf -y remove nfs-utils'
  impact 0.5
  tag check_id: 'C-85504r1165182_chk'
  tag severity: 'medium'
  tag gid: 'V-280943'
  tag rid: 'SV-280943r1165184_rule'
  tag stig_id: 'RHEL-10-200010'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85409r1165183_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  describe package('nfs-utils') do
    it { should_not be_installed }
  end
end
