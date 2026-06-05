control 'SV-281347' do
  title 'RHEL 10 must not forward Internet Protocol version 4 (IPv4) source-routed packets by default.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.

Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It must be disabled unless it is absolutely required, such as when IPv4 forwarding is enabled and the system is legitimately functioning as a router.

'
  desc 'check', 'Verify RHEL 10 does not accept IPv4 source-routed packets by default.

Check the value of the "net.ipv4.conf.default.accept_source_route" variable with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_source_route
net.ipv4.conf.default.accept_source_route = 0

If "net.ipv4.conf.default.accept_source_route" is not set to "0" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not forward IPv4 source-routed packets by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-ipv4_accept_source_route.conf

Add the following line to the file:

net.ipv4.conf.default.accept_source_route = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85908r1167189_chk'
  tag severity: 'medium'
  tag gid: 'V-281347'
  tag rid: 'SV-281347r1167191_rule'
  tag stig_id: 'RHEL-10-800150'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85813r1167190_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00078']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001102']
  tag nist: ['SC-5 a', 'SC-7 (4) (a)']

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'net.ipv4.conf.default.accept_source_route'
  value = 0
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
