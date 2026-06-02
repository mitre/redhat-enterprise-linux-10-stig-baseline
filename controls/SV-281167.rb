control 'SV-281167' do
  title 'RHEL 10 must require a unique superusers name upon booting into single-user and maintenance modes.'
  desc 'Having a nondefault grub superuser username makes password-guessing attacks less effective.'
  desc 'check', 'Verify RHEL 10 requires a unique superusers name upon booting into single-user and maintenance modes.

Verify that the boot loader superuser account has been set with the following command:

$ sudo grep -A1 "superusers" /etc/grub2.cfg
set superusers="<accountname>"
export superusers
password_pbkdf2 <accountname> ${GRUB2_PASSWORD}

Verify <accountname> is not a common name such as root, admin, or administrator.

If superusers contains easily guessable usernames, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have a unique username for the grub superuser account.

Edit the "/etc/grub.d/01_users" file and add or modify the following lines with a nondefault username for the superuser account:

set superusers="<accountname>"
export superusers

Once the superuser account has been added, update the "grub.cfg" file by regenerating the GRUB configuration with the following command:

$ sudo grub2-mkconfig -o /boot/grub2/grub.cfg --update-bls-cmdline

Reboot the system:

$ sudo reboot'
  impact 0.5
  tag check_id: 'C-85728r1166451_chk'
  tag severity: 'medium'
  tag gid: 'V-281167'
  tag rid: 'SV-281167r1166453_rule'
  tag stig_id: 'RHEL-10-600010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85633r1166452_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  grubfile = file(input('grub_conf_path'))

  describe grubfile do
    it { should exist }
  end

  superusers_account = grubfile.content.match(/set superusers="(?<superusers_account>\w+)"/)

  describe 'The GRUB superuser' do
    it "should be set in the GRUB config file ('#{grubfile}')" do
      expect(superusers_account).to_not be_nil, "No superuser account set in '#{grubfile}'"
    end
    unless superusers_account.nil?
      it 'should not contain easily guessable usernames' do
        expect(input('disallowed_grub_superusers')).to_not include(superusers_account[:superusers_account]), "Superuser account is set to easily guessable username '#{superusers_account[:superusers_account]}'"
      end
    end
  end
end
