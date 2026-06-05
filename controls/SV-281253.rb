control 'SV-281253' do
  title 'RHEL 10 must be configured so that Secure Shell (SSH) public host key files have mode "0644" or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', 'Verify RHEL 10 SSH public host key files have a mode of "0644" or less permissive with the following command:

Note: SSH public key files may be found in other directories on the system depending on the installation.

$ sudo stat -c "%a %n" /etc/ssh/*.pub
644 /etc/ssh/ssh_host_dsa_key.pub
644 /etc/ssh/ssh_host_ecdsa_key.pub
644 /etc/ssh/ssh_host_ed25519_key.pub
644 /etc/ssh/ssh_host_rsa_key.pub

If any "key.pub" file has a mode more permissive than "0644", this is a finding.'
  desc 'fix', 'Configure RHEL 10 SSH public host key files to have mode "0644" or less permissive.

Change the mode of public host key files under "/etc/ssh" to "0644" with the following command:

$ sudo chmod 0644 /etc/ssh/*key.pub

Restart the SSH daemon with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85814r1166709_chk'
  tag severity: 'medium'
  tag gid: 'V-281253'
  tag rid: 'SV-281253r1184654_rule'
  tag stig_id: 'RHEL-10-700500'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85719r1166710_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  ssh_host_key_dirs = input('ssh_host_key_dirs').join(' ')
  pub_keys = command("find #{ssh_host_key_dirs} -xdev -name '*.pub'").stdout.split("\n")
  mode = input('ssh_pub_key_mode')
  failing_keys = pub_keys.select { |key| file(key).more_permissive_than?(mode) }

  describe 'All SSH public keys on the filesystem' do
    it "should be less permissive than #{mode}" do
      expect(failing_keys).to be_empty, "Failing keyfiles:\n\t- #{failing_keys.join("\n\t- ")}"
    end
  end
end
