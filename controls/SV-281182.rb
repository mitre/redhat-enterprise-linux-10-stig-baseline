control 'SV-281182' do
  title 'RHEL 10 must enforce password complexity by requiring at least one special character to be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.

RHEL 10 uses "pwquality" as a mechanism to enforce password complexity. Note that to require special characters without degrading the "minlen" value, the credit value must be expressed as a negative number in "/etc/security/pwquality.conf".'
  desc 'check', 'Verify RHEL 10 enforces password complexity by requiring that at least one special character be used with the following command:

$ sudo grep -s ocredit /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
/etc/security/pwquality.conf:# ocredit = 0

If the value of "ocredit" is a positive number or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enforce password complexity by requiring that at least one special character be used by setting the "ocredit" option.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "ocredit" parameter:

ocredit = -1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag gid: 'V-281182'
  tag rid: 'SV-281182r1195424_rule'
  tag stig_id: 'RHEL-10-600230'
  tag fix_id: 'F-85648r1195423_fix'
  tag cci: ['CCI-001619', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  setting = 'ocredit'

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

    it "sets `#{setting}` to a negative value" do
      expect(setting_value.first.to_i).to be < 0, "#{setting} is not set to a negative value in pwquality.conf or pwquality.conf.d/*.conf"
    end
  end
end
