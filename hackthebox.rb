##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'msf/core'
require 'openssl'
require 'uri'

class MetasploitModule < Msf::Auxiliary
	 include Msf::Exploit::Remote::HttpClient
   Rex::Proto::Http::Response
	 
  def initialize
    super(
      'Name'           => 'HackTheBox's Shoutbox',
      'Description'    => 'This module simply do all HTB shoutbox things (ONLY reset support , bcz this module is under maintenance).',
      'Author'         => 'Touhid Shaikh aka Agent22',
      'License'        => MSF_LICENSE
    )

    register_options(
		[
			Opt::RPORT(443),
      Opt::RHOST("www.hackthebox.eu"),
      OptString.new('API',[true, 'HackTheBox USER API','api']),
      OptString.new('MACHINE',[true, "Machine Name Which u Want To reset",'machine'])
		],self.class)
  end

  def run
    begin
      uapi = datastore['API']
      machinename = datastore['MACHINE']

      #MAKING POST request here
      postrequest = "command=reset+#{machinename}" 


      res = send_request_cgi({
        'uri' => "/api/v2/htbcli/command?api_token=#{uapi}",
        'version' =>  "1.1",
        'method'  =>  "POST",
        'data'  =>  postrequest,
        'headers' =>  {
          'User-Agent' => "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Agent22",
          "Accept"  => "application/json, text/javascript, */*; q=0.01",
          "Accept-Language" => "en-US,en;q=0.5",
          "Accept-Encoding" => "gzip, deflate",
          "Content-Type" => "application/x-www-form-urlencoded; charset=UTF-8",
          "X-Requested-With" => "XMLHttpRequest",
          "Referer" => "https://www.hackthebox.eu/home",
        }
        },25)

      data = res.body
      print_status("optput : #{data}")
      print_status("#{machinename} issue reset request!"
        )

    end
    
    

  end
end
