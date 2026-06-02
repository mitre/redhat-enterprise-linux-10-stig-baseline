control 'SV-280960' do
  title 'RHEL 10 must disable the chrony daemon from acting as a server.'
  desc 'Minimizing the exposure of the server functionality of the chrony daemon diminishes the attack surface.'
  desc 'check', 'Verify RHEL 10 disables the chrony daemon from acting as a server with the following command:

$ sudo grep -w port /etc/chrony.conf
port 0

If the "port" option is not set to "0", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable the chrony daemon from acting as a server by adding/modifying the following line in the "/etc/chrony.conf" file:

port 0

Restart the chronyd service with the following command for the changes to take effect:

$ sudo systemctl restart chronyd'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-280960'
  tag rid: 'SV-280960r1165235_rule'
  tag stig_id: 'RHEL-10-200542'
  tag fix_id: 'F-85426r1165234_fix'
  tag cci: ['CCI-000381', 'CCI-000382']
  tag nist: ['CM-7 a', 'CM-7 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && file('/etc/chrony.conf').exist?
  }

  chrony_conf = ntp_conf('/etc/chrony.conf')

  describe chrony_conf do
    its('port') { should cmp 0 }
  end
end
