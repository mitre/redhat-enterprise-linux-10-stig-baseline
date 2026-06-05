control 'SV-281168' do
  title 'RHEL 10 must not assign an interactive login shell for system accounts.'
  desc 'Ensuring shells are not given to system accounts upon login makes it more difficult for attackers to use system accounts.'
  desc 'check', %q(Verify RHEL 10 system accounts do not have an interactive login shell with the following command:

$ awk -F: '($3<1000){print $1 ":" $3 ":" $7}' /etc/passwd
root:0:/bin/bash
bin:1:/sbin/nologin
daemon:2:/sbin/nologin
adm:3:/sbin/nologin
lp:4:/sbin/nologin

Identify the listed system accounts that have a shell other than nologin.

If any system account (other than the root account) has a login shell and it is not documented with the information system security officer (ISSO), this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that all noninteractive accounts on the system do not have an interactive shell assigned to them.

If the system account needs a shell assigned for mission operations, document the need with the ISSO.

Run the following command to disable the interactive shell for a specific noninteractive user account:

Replace <user> with the user that has a login shell.

$ sudo usermod --shell /sbin/nologin <user>

Do not perform the steps in this section on the root account. Doing so will cause the system to become inaccessible.'
  impact 0.5
  tag check_id: 'C-85729r1195415_chk'
  tag severity: 'medium'
  tag gid: 'V-281168'
  tag rid: 'SV-281168r1195416_rule'
  tag stig_id: 'RHEL-10-600020'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-85634r1166455_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']

  ignore_shells = input('non_interactive_shells').join('|')
  non_interactive_shells = passwd.where { uid.to_i < 1000 && !shell.match(ignore_shells) }.users - input('exempt_interactive_system_accounts')

  describe 'Non-interactive system accounts' do
    it 'should have non-interactive shells' do
      expect(non_interactive_shells).to be_empty, "Non-interactive system accounts with interactive shells:\n\t- #{non_interactive_shells.join("\n\t- ")}"
    end
  end
end
