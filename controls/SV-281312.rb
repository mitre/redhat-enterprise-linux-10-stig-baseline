control 'SV-281312' do
  title 'RHEL 10 must be configured to disable the Controller Area Network (CAN) kernel module.'
  desc 'Disabling CAN protects the system against exploitation of any flaws in its implementation.'
  desc 'check', "Verify RHEL 10 disables the ability to load the CAN kernel module with the following command:

$ sudo grep -rs can /etc/modprobe.conf /etc/modprobe.d/* | grep -v '#'
/etc/modprobe.d/can.conf:install can /bin/false
/etc/modprobe.d/can.conf:blacklist can

If the command does not return any output, or the lines are commented out, and use of CAN is not documented with the information system security officer as an operational requirement, this is a finding."
  desc 'fix', 'Configure RHEL 10 to disable the ability to load the CAN kernel module.

Create a drop-in if it does not already exist:

$ sudo vi /etc/modprobe.d/can.conf

Add the following lines to the file:

install can /bin/false
blacklist can'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-281312'
  tag rid: 'SV-281312r1167086_rule'
  tag stig_id: 'RHEL-10-701100'
  tag fix_id: 'F-85778r1167085_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('can_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    describe kernel_module('can') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
