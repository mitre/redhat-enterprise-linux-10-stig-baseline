control 'SV-281093' do
  title 'RHEL 10 must mount "/var/log/audit" with the "nosuid" option.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify RHEL 10 is configured so that "/var/log/audit" is mounted with the "nosuid" option:

$ mount | grep /var/log/audit
/dev/mapper/luks-4e45e1ad-5337-42c4-a19f-ee12ccc1d502 on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/var/log/audit" file system is mounted without the "nosuid" option, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to mount "/var/log/audit" with the "nosuid" option.

Modify "/etc/fstab" to use the "nosuid" option on the "/var/log/audit" directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-281093'
  tag rid: 'SV-281093r1165634_rule'
  tag stig_id: 'RHEL-10-400410'
  tag fix_id: 'F-85559r1165633_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  path = '/var/log/audit'
  option = 'nosuid'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
