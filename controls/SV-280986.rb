control 'SV-280986' do
  title 'RHEL 10 must be configured so that the rsyslog daemon does not accept log messages from other servers unless the server is being used for log aggregation.'
  desc "Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software, introduce misleading information into the system's logs, or fill the system's storage, leading to a denial of service.

If the system is intended to be a log aggregation server, its use must be documented with the information system security officer."
  desc 'check', "Note: If the SA can demonstrate that another tool (e.g., SPLUNK) is being used to manage log off-load and aggregation in lieu of rsyslog, this check is not applicable.

Verify RHEL 10 is not configured to receive remote logs using rsyslog.

Verify the setting with the following commands:

$ ss -tulnp | grep rsyslog

If no output is returned, rsyslog is not listening for remote logs.

If output appears, check for configured ports (514 is the default for syslog).

Check for remote logging configuration in rsyslog by examining the rsyslog configuration files:

$ sudo grep -E 'InputTCPServerRun|UDPServerRun|RELPServerRun|imtcp|imudp|imrelp' /etc/rsyslog.conf /etc/rsyslog.d/*

If this command returns uncommented lines enabling network listeners, the system is accepting remote logs. If this system is not documented and authorized as a log aggregation server, this is a finding.

Note: An error about no files or directories from the above commands may be returned. This is not a finding. Additionally, if a port option used together with a target and protocol is returned from inside an action block, this is not a finding."
  desc 'fix', 'Configure RHEL 10 to not receive remote logs using rsyslog.

Remove the lines in "/etc/rsyslog.conf" and any files in the "/etc/rsyslog.d" directory that match any of the following:

InputTCPServerRun
UDPServerRun
RELPServerRun
module(load="imtcp")
module(load="imudp")
module(load="imrelp")
input(type="imudp" port="514")
input(type="imtcp" port="514")
input(type="imrelp" port="514")

Restart the rsyslog daemon with the following command for the changes to take effect:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag check_id: 'C-85547r1184781_chk'
  tag severity: 'medium'
  tag gid: 'V-280986'
  tag rid: 'SV-280986r1184782_rule'
  tag stig_id: 'RHEL-10-200643'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85452r1165312_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002385']
  tag nist: ['CM-6 b', 'SC-5 a']
  tag 'host'
  tag 'container'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('is_log_aggregation_server') == true
    impact 0.0
    describe 'N/A' do
      skip 'This control is NA because the system is a log aggregation server.'
    end
  else
    modload = command('grep -i modload /etc/rsyslog.conf /etc/rsyslog.d/*').stdout.strip
    imtcp = command(%q(grep -i 'load="imtcp"' /etc/rsyslog.conf /etc/rsyslog.d/*)).stdout.strip
    imrelp = command(%q(grep -i 'load="imrelp"' /etc/rsyslog.conf /etc/rsyslog.d/*)).stdout.strip
    serverrun = command('grep -i serverrun /etc/rsyslog.conf /etc/rsyslog.d/*').stdout.strip
    ports = command(%q(grep -i 'port="\S*"' /etc/rsyslog.conf /etc/rsyslog.d/*)).stdout.strip

    describe 'modload' do
      it 'is not configured to receive remote logs' do
        expect(modload).to be_empty, "modload settings found:\n#{modload}"
      end
    end
    describe 'imtcp' do
      it 'is not configured to receive remote logs' do
        expect(imtcp).to be_empty, "imtcp settings found:\n#{imtcp}"
      end
    end
    describe 'imrelp' do
      it 'is not configured to receive remote logs' do
        expect(imrelp).to be_empty, "imrelp settings found:\n#{imrelp}"
      end
    end
    describe 'serverrun config' do
      it 'is not configured to receive remote logs' do
        expect(serverrun).to be_empty, "serverrun settings found:\n#{serverrun}"
      end
    end
    describe 'ports' do
      it 'are not configured to receive remote logs' do
        expect(ports).to be_empty, "port settings found:\n#{ports}"
      end
    end
  end
end
