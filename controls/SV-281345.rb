control 'SV-281345' do
  title 'RHEL 10 must use reverse path filtering on all Internet Protocol version 4 (IPv4) interfaces.'
  desc 'Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface on which they were received. It must not be used on systems that are routers for complicated networks but is helpful for end hosts and routers serving small networks.

'
  desc 'check', 'Verify RHEL 10 uses reverse path filtering on all IPv4 interfaces.

Check the value of the "net.ipv4.conf.all.rp_filter" variable with the following command:

$ sudo sysctl net.ipv4.conf.all.rp_filter
net.ipv4.conf.all.rp_filter = 1

If "net.ipv4.conf.all.rp_filter" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use reverse path filtering on all IPv4 interfaces.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-ipv4_rp_filter.conf

Add the following line to the file:

net.ipv4.conf.all.rp_filter = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85906r1167183_chk'
  tag severity: 'medium'
  tag gid: 'V-281345'
  tag rid: 'SV-281345r1167185_rule'
  tag stig_id: 'RHEL-10-800130'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85811r1167184_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00076']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001100']
  tag nist: ['SC-5 a', 'SC-7 (2)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'net.ipv4.conf.all.rp_filter'
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
