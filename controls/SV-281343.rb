control 'SV-281343' do
  title 'RHEL 10 must log Internet Protocol version 4 (IPv4) packets with impossible addresses.'
  desc 'The presence of "martian" packets (which have impossible addresses), as well as spoofed packets, source-routed packets, and redirects, could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.

'
  desc 'check', 'Verify RHEL 10 logs IPv4 martian packets.

Check the value of the "net.ipv4.conf.all.log_martians" variable with the following command:

$ sudo sysctl net.ipv4.conf.all.log_martians
net.ipv4.conf.all.log_martians = 1

If "net.ipv4.conf.all.log_martians" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to log martian packets on IPv4 interfaces.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/99-ipv4_log_martians.conf

Add the following line to the file:

net.ipv4.conf.all.log_martians=1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-85904r1167177_chk'
  tag severity: 'medium'
  tag gid: 'V-281343'
  tag rid: 'SV-281343r1167179_rule'
  tag stig_id: 'RHEL-10-800110'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85809r1167178_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00074']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001098']
  tag nist: ['SC-5 a', 'SC-7 c']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'net.ipv4.conf.all.log_martians'
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
