require_relative '../servers'

module Set5
  module_function

  def challenge37(srv_port, username)
    s = TCPSocket.new('localhost', srv_port)
    s.puts username
    s.puts 0.to_s(16)

    salt = s.gets.chomp.extend(Utils::HexString).to_ascii
    b_pub = s.gets.chomp.hex
    key = Servers::SRPServer.hash(0)
    s.puts Servers::SRPServer.hmac(key, salt)

    s.gets.chomp
  end
end
