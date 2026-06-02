control 'SV-280945' do
  title 'RHEL 10 must not have the "gssproxy" package installed.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations (e.g., key missions, functions).

The gssproxy package is a proxy for GSS API credential handling and could expose secrets on some networks. It is not needed for normal function of the operating system.'
  desc 'check', 'Note: If Network File System (NFS) mounts are authorized and in use on the system, this control is not applicable.

Verify RHEL 10 does not have the "gssproxy" package installed with the following command:

$ sudo dnf list --installed gssproxy
Error: No matching Packages to list

If the "gssproxy" package is installed and is not documented with the information system security officer as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not have the "gssproxy" package installed with the following command:

$ sudo dnf -y remove gssproxy'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-280945'
  tag rid: 'SV-280945r1184750_rule'
  tag stig_id: 'RHEL-10-200030'
  tag fix_id: 'F-85411r1165189_fix'
  tag cci: ['CCI-000381', 'CCI-000366']
  tag nist: ['CM-7 a', 'CM-6 b']
  tag 'host'
  tag 'container'

  if input('gssproxy_required')
    describe package('gssproxy') do
      it { should be_installed }
    end
  else
    describe package('gssproxy') do
      it { should_not be_installed }
    end
  end
end
