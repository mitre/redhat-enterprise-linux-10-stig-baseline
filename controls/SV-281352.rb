control 'SV-281352' do
  title 'RHEL 10 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

The ability to send ICMP redirects is only appropriate for systems acting as routers."
  desc 'check', 'Verify RHEL 10 does not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Check the value of the "net.ipv4.conf.default.send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.send_redirects
net.ipv4.conf.default.send_redirects=0

If "net.ipv4.conf.default.send_redirects" is not set to "0" and is not documented with the information system security officer as an operational requirement or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not allow interfaces to perform IPv4 ICMP redirects by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_send_redirects.conf

Add the following line to the file:

net.ipv4.conf.default.send_redirects = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-281352'
  tag rid: 'SV-281352r1184706_rule'
  tag stig_id: 'RHEL-10-800200'
  tag fix_id: 'F-85818r1184705_fix'
  tag cci: ['CCI-000366', 'CCI-002385', 'CCI-001107']
  tag nist: ['CM-6 b', 'SC-5 a', 'SC-7 (4) (e)']
  tag 'host'

  only_if('This system is acting as a router on the network; this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  if input('send_redirects')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  elsif input('ipv4_enabled') == false
    impact 0.0
    describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
    end
  else

    parameter = 'net.ipv4.conf.default.send_redirects'
    value = 0
    regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

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
