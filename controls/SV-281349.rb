control 'SV-281349' do
  title 'RHEL 10 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.'
  desc 'Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.

Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network.'
  desc 'check', 'Verify RHEL 10 ignores ICMP echoes sent to a broadcast address.

Check the value of the "net.ipv4.icmp_echo_ignore_broadcasts" variable with the following command:

$ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1

If "net.ipv4.icmp_echo_ignore_broadcasts" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to ignore Internet Protocol version 4 (IPv4) ICMP echoes sent to a broadcast address.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_icmp_echo_ignore_broadcasts.conf

Add the following line to the file:

net.ipv4.icmp_echo_ignore_broadcasts = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-281349'
  tag rid: 'SV-281349r1167197_rule'
  tag stig_id: 'RHEL-10-800170'
  tag fix_id: 'F-85815r1167196_fix'
  tag cci: ['CCI-000366', 'CCI-002385', 'CCI-001104']
  tag nist: ['CM-6 b', 'SC-5 a', 'SC-7 (4) (c)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'net.ipv4.icmp_echo_ignore_broadcasts'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  if input('ipv4_enabled') == false
    impact 0.0
    describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
    end
  else
    describe kernel_parameter(parameter) do
      its('value') { should eq value }
    end

    search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

    correct_result = search_results.any? { |line| line.match(regexp) }
    incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

    describe 'Kernel config files' do
      it "should configure '#{parameter}'" do
        expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
      end
      unless incorrect_results.nil?
        it 'should not have incorrect or conflicting setting(s) in the config files' do
          expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
        end
      end
    end
  end
end
