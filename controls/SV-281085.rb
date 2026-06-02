control 'SV-281085' do
  title 'RHEL 10 must enforce mode "0600" or less permissive for Secure Shell (SSH) private host key files.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', 'Verify RHEL 10 enforces mode "0600" for SSH private host key files with the following command:

$ sudo stat -c "%a %n" /etc/ssh/*_key
600 /etc/ssh/ssh_host_ecdsa_key
600 /etc/ssh/ssh_host_ed25519_key
600 /etc/ssh/ssh_host_rsa_key

If any private host key file has a mode more permissive than "0600", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enforce mode "0600" for SSH private host key files with the following command:

$ sudo chmod 0600 /etc/ssh/ssh_host*key

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85646r1195407_chk'
  tag severity: 'medium'
  tag gid: 'V-281085'
  tag rid: 'SV-281085r1195409_rule'
  tag stig_id: 'RHEL-10-400340'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85551r1195408_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
