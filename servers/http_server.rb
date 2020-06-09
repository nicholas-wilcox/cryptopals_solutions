require 'net/http'

module Servers
  class HTTPServer

    attr_reader :server
    attr_accessor :port

    def initialize(port, message = '')
      @port = port
      @server = WEBrick::HTTPServer.new({
        Port: @port
      })
      @message = message
    end

    def message
      get_from('/message', @port).body
    end

    def message=(value)
      post_text('/message', @port, value).body
    end

    def routine
      trap('INT') { @server.shutdown }
      @server.start
    end

    def mount
      @server.mount_proc('/message') do |req, res|
        case req.request_method
        when 'POST'
          @message = req.body
        when 'GET'
          res.body = @message
        end
      end
    end

    def post_text(endpoint, port, text)
      Net::HTTP.start('localhost', port) do |http|
        http.post(endpoint, text, { 'Content-Type': 'text/plain' })
      end
    end

    def post_json(endpoint, port, obj)
      Net::HTTP.start('localhost', port) do |http|
        http.post(endpoint, obj.to_json, { 'Content-Type': 'application/json' })
      end
    end

    def get_from(endpoint, port)
      Net::HTTP.start('localhost', port) do |http|
        http.get(endpoint)
      end
    end
    
    def shutdown
      @server.shutdown
    end
  end
end
