control 'SV-280947' do
  title 'RHEL 10 must not have a Trivial File Transfer Protocol (TFTP) server package installed unless it is required by the mission, and if required, the TFTP daemon must be configured to operate in secure mode.'
  desc 'Removing the "tftp-server" package decreases the risk of the accidental (or intentional) activation of TFTP services.

If TFTP is required for operational support (such as transmission of router configurations), its use must be documented with the information systems security manager (ISSM), restricted to only authorized personnel, and have access control rules established.

Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.'
  desc 'check', 'Note: If TFTP is not required, it must not be installed. If TFTP is not installed, this rule is not applicable.

Verify RHEL 10 is configured so that TFTP operates in secure mode if installed.

Determine if TFTP server is installed with the following command:

$ sudo dnf list --installed | grep tftp-server
tftp-server.x86_64                                   5.2-48.el10                     @rhel-10-for-x86_64-appstream-rpms

If the TFTP server package is installed and is not required, or if it is not documented with the ISSM, this is a finding.

Verify the TFTP daemon, if tftp.server is installed, is configured to operate in secure mode with the following command:

$ grep -i execstart /usr/lib/systemd/system/tftp.service
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

Note: The "-s" option ensures the TFTP server only serves files from the specified directory, which is a security measure to prevent unauthorized access to other parts of the file system.

If the "-s" option is not present in the "ExecStart" line, or if the line is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that TFTP operates in secure mode if installed.

If TFTP server is not required, remove it with the following command:

$ sudo dnf -y remove tftp-server

Configure the TFTP daemon to operate in secure mode with the following command:

$ sudo systemctl edit tftp.service

In the editor, enter:

[Service]
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

After making changes, reload the systemd daemon and restart the TFTP service as follows:

$ sudo systemctl daemon-reload
$ sudo systemctl restart tftp.service'
  impact 0.5
  tag check_id: 'C-85508r1165194_chk'
  tag severity: 'medium'
  tag gid: 'V-280947'
  tag rid: 'SV-280947r1165196_rule'
  tag stig_id: 'RHEL-10-200050'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85413r1165195_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  if input('tftp_required')
    describe package('tftp-server') do
      it { should be_installed }
    end

    describe file('/usr/lib/systemd/system/tftp.service') do
      it { should exist }
      its('content') { should match(/ExecStart=.*\s-s(\s|$)/) }
    end
  else
    describe package('tftp-server') do
      it { should_not be_installed }
    end
  end
end
