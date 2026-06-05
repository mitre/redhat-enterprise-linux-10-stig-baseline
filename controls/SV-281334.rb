control 'SV-281334' do
  title 'RHEL 10 must enforce that network interfaces not be in promiscuous mode.'
  desc 'Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow them to collect information such as login IDs, passwords, and key exchanges between systems.

If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the information systems security officer (ISSO) and restricted to authorized personnel only.'
  desc 'check', 'Verify RHEL 10 network interfaces are not in promiscuous mode with the following command:

$ sudo ip link | grep -i promisc

If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding.'
  desc 'fix', 'Configure RHEL 10 network interfaces to turn off promiscuous mode unless approved by the ISSO and documented.

Set the promiscuous mode of an interface to "off" with the following command:

$ sudo ip link set dev <devicename> multicast off promisc off'
  impact 0.5
  tag check_id: 'C-85895r1167150_chk'
  tag severity: 'medium'
  tag gid: 'V-281334'
  tag rid: 'SV-281334r1167152_rule'
  tag stig_id: 'RHEL-10-800020'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-85800r1167151_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('promiscuous_mode_permitted')
    describe command('ip link | grep -i promisc') do
      its('stdout.strip') { should_not match(/^$/) }
    end
  else
    describe command('ip link | grep -i promisc') do
      its('stdout.strip') { should match(/^$/) }
    end
  end
end
