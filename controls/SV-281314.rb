control 'SV-281314' do
  title 'RHEL 10 must disable the Transparent Inter Process Communication (TIPC) kernel module.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The TIPC is a protocol that is specially designed for intra-cluster communication. It can be configured to transmit messages either on User Datagram Protocol (UDP) or directly across Ethernet. Message delivery is sequence guaranteed, loss free, and flow controlled. Disabling TIPC protects the system against exploitation of any flaws in its implementation.'
  desc 'check', "Verify RHEL 10 disables the ability to load the tipc kernel module with the following command:

$ sudo grep -rs tipc /etc/modprobe.conf /etc/modprobe.d/* | grep -v '#'
/etc/modprobe.d/tipc-blacklist.conf:install tipc /bin/false
/etc/modprobe.d/tipc-blacklist.conf:blacklist tipc

If the command does not return any output, or the lines are commented out, and use of tipc is not documented with the information system security officer as an operational requirement, this is a finding."
  desc 'fix', 'Configure RHEL 10 to disable the ability to load the tipc kernel module.

Create a drop-in if it does not already exist:

$ sudo vi /etc/modprobe.d/tipc.conf

Add the following lines to the file:

install tipc /bin/false
blacklist tipc'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-281314'
  tag rid: 'SV-281314r1184771_rule'
  tag stig_id: 'RHEL-10-701120'
  tag fix_id: 'F-85780r1167091_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('tipc_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    describe kernel_module('tipc') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
