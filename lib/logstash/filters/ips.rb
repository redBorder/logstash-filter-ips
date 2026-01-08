# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"

require_relative "util/malware_constant"
require_relative "util/aerospike_config"
require_relative "store/aerospike_store"

class LogStash::Filters::Ips < LogStash::Filters::Base
  include MalwareConstant
  include Aerospike

  config_name "ips"

  config :aerospike_server,          :validate => :string,  :default => "",                           :required => false
  config :aerospike_namespace,       :validate => :string,  :default => "malware",                    :required => false
  config :counter_store_counter,     :validate => :boolean, :default => false,                        :required => false
  config :flow_counter,              :validate => :boolean, :default => false,                        :required => false
  config :reputation_servers,        :validate => :array,   :default => ["127.0.0.1:7777"],           :required => false

  # DATASOURCE="rb_flow"
  DELAYED_REALTIME_TIME = 15

  public
  def register
    @dimensions = ['timestamp', 'src', 'dst', 'sensor_name', 'sensor_id', 'client_mac', 'sensor_uuid']

    # Add instance variables
    @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
    @aerospike_server = @aerospike_server.sample if @aerospike_server.instance_of?(Array)
    @aerospike = nil
    @aerospike_store = nil
    register_aerospike_and_set_aerospike_store
  end

  def register_aerospike_and_set_aerospike_store
    begin
      host, port = @aerospike_server.split(':')
      @aerospike = Client.new(Host.new(host, port))
      @aerospike_store = AerospikeStore.new(@aerospike, @aerospike_namespace, @reputation_servers)
    rescue Aerospike::Exceptions::Aerospike => e
      @aerospike = nil
      @aerospike_store = nil
      @logger.error(e.message)
    end
  end

  def size_to_range(size)
    range = nil
    if size < 1024
      range = '<1kB'
    elsif size >= 1024 && size < (1024 * 1024)
      range = '1kB-1MB'
    elsif size >= (1024 * 1024) && size < (10 * 1024 * 1024)
      range = '1MB-10MB'
    elsif size >= (10 * 1024 * 1024) && size < (50 * 1024 * 1024)
      range = '10MB-50MB'
    elsif size >= (50 * 1024 * 1024 && size < (100 * 1024 * 1024))
      range = '50MB-100MB'
    elsif size >= (100 * 1024 * 1024) && size < (500 * 1024 * 1024)
      range = '100MB-500MB'
    elsif size >= (500 * 1024 * 1024) && size < (1024 * 1024 * 1024)
      range = '500MB-1GB'
    elsif size >= (1024 * 1024 * 1024)
      range = '>1GB'
    end

    range
  end

  def filter(event)
    # Solve the problem that happen when:
    # at time of registering the plugin the
    # aerospike was not there
    register_aerospike_and_set_aerospike_store if @aerospike.nil?

    message = {}
    message = event.to_hash

    generated_events = []

    if message['sha256']
      to_druid = {}
      timestamp = message['timestamp']
      hash = message['sha256']
      to_druid['hash'] = hash
      to_druid['timestamp'] = timestamp
      to_druid['type'] = 'ips'

      file_hostname = message['file_hostname'] || ''
      file_uri = message['file_uri'] || ''

      if !file_hostname.empty? && !file_uri.empty?
        url = "http://#{file_hostname}#{file_uri}"
        to_druid['url'] = url
        @aerospike_store.update_hash_times(timestamp, url, 'url')
      end

      begin
        file_name = File.basename(file_hostname + file_uri)
      rescue
        file_name = file_uri
      end

      to_druid['file_name'] = file_name unless file_name.nil? || file_name.empty?

      @dimensions.each do |dimension|
        value = message[dimension]

        to_druid[dimension] = value unless value.nil?
      end

      file_size = message['file_size']

      to_druid['file_size'] = size_to_range(file_size) unless file_size.nil?

      if message.key?('file_hostname')
        to_druid['application_id_name'] = 'http'
      elsif message.key?('email_sender')
        to_druid['application_id_name'] = 'smtp'
      elsif message.key?('ftp_user')
        to_druid['application_id_name'] = 'ftp'
        to_druid['client_id'] = message['ftp_user']
      elsif message.key?('smb_uid')
        to_druid['application_id_name'] = 'smb'
        to_druid['client_id'] = message['smb_uid']
      end

      @aerospike_store.update_hash_times(timestamp, hash, 'hash')

      hash_message = @aerospike_store.enrich_hash_scores(to_druid)
      url_message = @aerospike_store.enrich_url_scores(hash_message)
      ip_message = @aerospike_store.enrich_ip_scores(url_message)

      generated_events.push(LogStash::Event.new(ip_message))

      generated_events.each do |e|
        yield e
      end
    end
    event.cancel
  end
end
