control 'SV-281313' do
  title 'RHEL 10 must disable the Stream Control Transmission Protocol (SCTP) kernel module.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect unused protocols can result in a system compromise.

The SCTP is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. Disabling SCTP protects the system against exploitation of any flaws in its implementation.'
  desc 'check', "Verify RHEL 10 disables the ability to load the sctp kernel module with the following command:

$ sudo grep -rs sctp /etc/modprobe.conf /etc/modprobe.d/* | grep -v '#'
/etc/modprobe.d/sctp-blacklist.conf:install sctp /bin/false
/etc/modprobe.d/sctp-blacklist.conf:blacklist sctp

If the command does not return any output, or the lines are commented out, and use of sctp is not documented with the information system security officer as an operational requirement, this is a finding."
  desc 'fix', 'Configure RHEL 10 to disable the ability to load the sctp kernel module.

Create a drop-in if it does not already exist:

$ sudo vi /etc/modprobe.d/sctp.conf

Add the following lines to the file:

install sctp /bin/false
blacklist sctp'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-281313'
  tag rid: 'SV-281313r1184770_rule'
  tag stig_id: 'RHEL-10-701110'
  tag fix_id: 'F-85779r1167088_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('sctp_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    describe kernel_module('sctp') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
