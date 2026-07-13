control 'SV-281231' do
  title 'RHEL 10 must be configured so that the Network File System (NFS) is configured to use RPCSEC_GSS.'
  desc 'When an NFS server is configured to use RPCSEC_SYS, a selected userid and groupid are used to handle requests from the remote user. The userid and groupid could mistakenly or maliciously be set incorrectly. The RPCSEC_GSS method of authentication uses certificates on the server and client systems to more securely authenticate the remote mount request.'
  desc 'check', 'Note: If no NFS mounts are configured, this requirement is not applicable.

Verify RHEL 10 has the "sec" option configured for all NFS mounts with the following command:

$ sudo grep nfs /etc/fstab
192.168.22.2:/mnt/export /data nfs4 rw,nosuid,nodev,noexec,sync,soft,sec=krb5p:krb5i:krb5

If the system is mounting file systems via NFS and has the sec option without the "krb5:krb5i:krb5p" settings, the "sec" option has the "sys" setting, or the "sec" option is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the "/etc/fstab" file "sec" option is defined for each NFS mounted file system, and the "sec" option does not have the "sys" setting.

Ensure the "sec" option is defined as "krb5p:krb5i:krb5".'
  impact 0.5
  tag check_id: 'C-85792r1166643_chk'
  tag severity: 'medium'
  tag gid: 'V-281231'
  tag rid: 'SV-281231r1166645_rule'
  tag stig_id: 'RHEL-10-700115'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85697r1166644_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  required_sec_values = %w[krb5 krb5i krb5p]
  nfs_file_systems = etc_fstab.nfs_file_systems.params
  failing_mounts = nfs_file_systems.reject do |mnt|
    sec_option = mnt['mount_options'].find { |option| option.start_with?('sec=') }
    next false if sec_option.nil?

    sec_values = sec_option.split('=', 2).last.split(':')
    (required_sec_values - sec_values).empty? && (sec_values - required_sec_values).empty?
  end

  if nfs_file_systems.empty?
    impact 0.0
    describe 'N/A' do
      skip 'No NFS mounts are configured'
    end
  else
    describe 'Any mounted Network File System (NFS)' do
      it 'should have sec configured for RPCSEC_GSS' do
        formatted_mounts = failing_mounts.map { |mnt| "#{mnt['device_name']} #{mnt['mount_point']} #{mnt['file_system_type']} #{mnt['mount_options'].join(',')}" }
        expect(failing_mounts).to be_empty, "NFS mounts without sec=krb5p:krb5i:krb5:\n\t- #{formatted_mounts.join("\n\t- ")}"
      end
    end
  end
end
