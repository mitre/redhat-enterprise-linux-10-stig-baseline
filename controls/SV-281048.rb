control 'SV-281048' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) server configuration file is owned by "root".'
  desc 'Service configuration files enable or disable features of their respective services, which if configured incorrectly can lead to insecure and vulnerable configurations. Therefore, service configuration files must be owned by the correct group to prevent unauthorized changes.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/ssh/sshd_config" file and the contents of "/etc/ssh/sshd_config.d" are owned by root with the following command:

$ sudo find /etc/ssh/sshd_config /etc/ssh/sshd_config.d -exec stat -c "%U %n" {} \\;
root /etc/ssh/sshd_config
root /etc/ssh/sshd_config.d
root /etc/ssh/sshd_config.d/50-cloud-init.conf
root /etc/ssh/sshd_config.d/50-redhat.conf

If the "/etc/ssh/sshd_config" file or "/etc/ssh/sshd_config.d" or any files in the "sshd_config.d" directory do not have an owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the "/etc/ssh/sshd_config" file and the contents of "/etc/ssh/sshd_config.d" are owned by "root" with the following command:

$ sudo chown -R root /etc/ssh/sshd_config /etc/ssh/sshd_config.d'
  impact 0.5
  tag check_id: 'C-85609r1165497_chk'
  tag severity: 'medium'
  tag gid: 'V-281048'
  tag rid: 'SV-281048r1184648_rule'
  tag stig_id: 'RHEL-10-400155'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85514r1165498_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe file('/etc/ssh/sshd_config') do
    it { should exist }
    it { should be_owned_by 'root' }
  end
end
