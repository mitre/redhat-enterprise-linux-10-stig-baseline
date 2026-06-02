control 'SV-281230' do
  title 'RHEL 10 must prevent files with the "setuid" and "setgid" bit set from being executed on file systems that are imported via Network File System (NFS).'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Note: If no NFS mounts are configured, this requirement is not applicable.

Verify RHEL 10 has the "nosuid" option configured for all NFS mounts with the following command:

$ sudo grep nfs /etc/fstab
192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5:krb5i:krb5p

If the system is mounting file systems via NFS and the "nosuid" option is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to prevent files with the "setuid" and "setgid" bit set from being executed on file systems that are imported via NFS.

Update each NFS mounted file system to use the "nosuid" option on file systems that are being imported via NFS.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-281230'
  tag rid: 'SV-281230r1166642_rule'
  tag stig_id: 'RHEL-10-700110'
  tag fix_id: 'F-85696r1166641_fix'
  tag cci: ['CCI-000366', 'CCI-000213']
  tag nist: ['CM-6 b', 'AC-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  option = 'nosuid'
  nfs_file_systems = etc_fstab.nfs_file_systems.params
  failing_mounts = nfs_file_systems.reject { |mnt| mnt['mount_options'].include?(option) }

  if nfs_file_systems.empty?
    impact 0.0
    describe 'N/A' do
      skip 'No NFS mounts are configured'
    end
  else
    describe 'Any mounted Network File System (NFS)' do
      it "should have '#{option}' set" do
        expect(failing_mounts).to be_empty, "NFS without '#{option}' set:\n\t- #{failing_mounts.join("\n\t- ")}"
      end
    end
  end
end
