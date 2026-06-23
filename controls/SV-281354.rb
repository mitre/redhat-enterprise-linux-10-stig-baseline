control 'SV-281354' do
  title 'RHEL 10 must not accept router advertisements on all Internet Protocol version 6 (IPv6) interfaces.'
  desc 'An illicit router advertisement message could result in a man-in-the-middle attack.

'
  desc 'check', 'Note: If IPv6 is disabled on the system, this requirement is not applicable.

Verify RHEL 10 does not accept router advertisements on all IPv6 interfaces, unless the system is a router.

Check that "net.ipv6.conf.all.accept_ra" is set to not accept router advertisements by using the following command:

$ sudo sysctl net.ipv6.conf.all.accept_ra
net.ipv6.conf.all.accept_ra = 0

If "net.ipv6.conf.all.accept_ra" is not set to "0" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not accept router advertisements on all IPv6 interfaces, unless the system is a router.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_accept_ra.conf

Add the following line to the file:

net.ipv6.conf.all.accept_ra = 0

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85915r1167210_chk'
  tag severity: 'medium'
  tag gid: 'V-281354'
  tag rid: 'SV-281354r1167212_rule'
  tag stig_id: 'RHEL-10-800220'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85820r1167211_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00085']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001109']
  tag nist: ['SC-5 a', 'SC-7 (5)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('accept_ra_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  elsif input('ipv6_enabled') == false
    impact 0.0
    describe 'IPv6 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv6 is disabled on the system, this requirement is Not Applicable.'
    end
  else

    parameter = 'net.ipv6.conf.all.accept_ra'
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
