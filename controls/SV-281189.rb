control 'SV-281189' do
  title 'RHEL 10 must require the change of at least four character classes when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. 

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex a password is, the greater the number of possible combinations that must be tested before the password is compromised.'
  desc 'check', 'Verify RHEL 10 sets the value of the "minclass" option in "/etc/security/pwquality.conf" with the following command:

$ sudo grep -s minclass /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
/etc/security/pwquality.conf:minclass = 4

If the value of "minclass" is set to less than "4" or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to require the change of at least four character classes when passwords are changed by setting the "minclass" option.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "minclass" parameter:

minclass = 4'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: 'V-281189'
  tag rid: 'SV-281189r1195442_rule'
  tag stig_id: 'RHEL-10-600300'
  tag fix_id: 'F-85655r1195441_fix'
  tag cci: ['CCI-000195', 'CCI-004066']
  tag nist: ['IA-5 (1) (b)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  setting = 'minclass'
  expected_value = input('minclass')

  describe 'pwquality.conf settings' do
    let(:config_files) do
      ['/etc/security/pwquality.conf'] +
        command("find /etc/security/pwquality.conf.d -maxdepth 1 -type f -name '*.conf' | sort").stdout.lines.map(&:strip)
    end

    let(:setting_value) do
      config_files.flat_map do |path|
        next [] unless file(path).file?

        config = parse_config_file(path, multiple_values: true)
        value = config.params[setting]
        value.is_a?(Integer) ? [value] : Array(value)
      end
    end

    it "has `#{setting}` set" do
      expect(setting_value).not_to be_empty, "#{setting} is not set in pwquality.conf or pwquality.conf.d/*.conf"
    end

    it "only sets `#{setting}` once" do
      expect(setting_value.length).to eq(1), "#{setting} is set more than once in pwquality.conf or pwquality.conf.d/*.conf"
    end

    it "sets `#{setting}` to at least #{expected_value}" do
      expect(setting_value.first.to_i).to be >= expected_value.to_i, "#{setting} is set to less than #{expected_value} in pwquality.conf or pwquality.conf.d/*.conf"
    end
  end
end
