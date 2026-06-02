control 'SV-280961' do
  title 'RHEL 10 must disable network management of the chrony daemon.'
  desc 'Not exposing the management interface of the chrony daemon on the network diminishes the attack space.'
  desc 'check', 'Verify RHEL 10 disables network management of the chrony daemon with the following command:

$ sudo grep -w cmdport /etc/chrony.conf
cmdport 0

If the "cmdport" option is not set to "0", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable network management of the chrony daemon by adding/modifying the following line in the "/etc/chrony.conf" file:

cmdport 0

Restart the chronyd service with the following command for the changes to take effect:

$ sudo systemctl restart chronyd'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag gid: 'V-280961'
  tag rid: 'SV-280961r1165238_rule'
  tag stig_id: 'RHEL-10-200543'
  tag fix_id: 'F-85427r1165237_fix'
  tag cci: ['CCI-000381', 'CCI-000382']
  tag nist: ['CM-7 a', 'CM-7 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && file('/etc/chrony.conf').exist?
  }

  chrony_conf = ntp_conf('/etc/chrony.conf')

  describe chrony_conf do
    its('cmdport') { should cmp 0 }
  end
end
