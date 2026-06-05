control 'SV-281356' do
  title 'RHEL 10 must not forward Internet Protocol version 6 (IPv6) source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when forwarding is enabled and the system is functioning as a router.

'
  desc 'check', 'Note: If IPv6 is disabled on the system, this requirement is not applicable.

Verify RHEL 10 does not accept IPv6 source-routed packets.

Check the value of the "net.ipv6.conf.all.accept_source_route" variable with the following command:

$ sudo sysctl net.ipv6.conf.all.accept_source_route
net.ipv6.conf.all.accept_source_route = 0

If "net.ipv6.conf.all.accept_source_route" is not set to "0" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not accept IPv6 source-routed packets.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv6_accept_source_route.conf

Add the following line to the file:

net.ipv6.conf.all.accept_source_route = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85917r1167216_chk'
  tag severity: 'medium'
  tag gid: 'V-281356'
  tag rid: 'SV-281356r1167218_rule'
  tag stig_id: 'RHEL-10-800240'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85822r1167217_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00087']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001111']
  tag nist: ['SC-5 a', 'SC-7 (7)']

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'net.ipv6.conf.all.accept_source_route'
  value = 0
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  if input('ipv6_enabled') == false
    impact 0.0
    describe 'IPv6 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv6 is disabled on the system, this requirement is Not Applicable.'
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
