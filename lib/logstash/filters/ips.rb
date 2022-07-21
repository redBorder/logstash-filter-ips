# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require_relative "util/ips_constant"
require_relative "util/aerospike_config"
require_relative "store/aerospike_store"

class LogStash::Filters::Ips < LogStash::Filters::Base
  include IpsConstant
  include Aerospike

  config_name "ips"

  config :aerospike_server,          :validate => :string,  :default => "",                             :required => false
  config :aerospike_namespace,       :validate => :string,  :default => "malware",                      :required => false
  config :counter_store_counter,     :validate => :boolean, :default => false,                          :required => false
  config :flow_counter,              :validate => :boolean, :default => false,                          :required => false
  config :reputation_servers,        :validate => :array,   :default => ["127.0.0.1:7777"],             :require => false

  # DATASOURCE="rb_flow"
  DELAYED_REALTIME_TIME = 15

  public
  def register
    # Add instance variables
    @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
    @aerospike = Client.new(@aerospike_server.first.split(":").first)
    @aerospike_store = AerospikeStore.new(@aerospike, @aerospike_namespace,  @reputation_servers)
  end # def register

  public

  def size_to_range(size)
    range  = nil
    if (size < 1024)
        range =  "<1kB"
    elsif(size >= 1024 && size < (1024*1024))
        range = "1kB-1MB"
    elsif(size >= (1024*1024) && size < (10*1024*1024))
        range = "1MB-10MB"
    elsif(size >= (10*1024*1024) && size < (50*1024*1024))
        range = "10MB-50MB"
    elsif(size >= (50*1024*1024) && size < (100*1024*1024))
        range = "50MB-100MB"
    elsif(size >= (100*1024*1024) && size < (500*1024*1024))
        range = "100MB-500MB"
    elsif(size >= (500*1024*1024) && size < (1024*1024*1024))
        range = "500MB-1GB"
    elsif(size >= (1024*1024*1024))
        range = ">1GB"
    end

    return range
  end

  def filter(event)
    message = {}
    message = event.to_hash

    generated_events = [] 

    if message[SHA256] 
      to_druid = {}
      timestamp = message[TIMESTAMP]
      hash = message[SHA256]
      to_druid[HASH] = hash
      to_druid[TIMESTAMP] = timestamp
      to_druid[TYPE] = "ips"

      file_hostname = message[FILE_HOSTNAME]
      file_uri = message[FILE_URI]

      if file_hostname and file_uri
        url = "http://" + file_hostname + file_uri
        to_druid[URL] = url
        @aerospike_store.update_hash_times(timestamp, url, "url")
      end

      file_name = File.basename(file_hostname, file_uri)
      
      to_druid[FILE_NAME] = file_name unless file_name.nil?

      dimensions.each do |dimension|
        value = message[dimension]
        
        to_druid[dimension] = value unless value.nil?
      end

      file_size = message[FILE_SIZE]

      to_druid[FILE_SIZE] = size_to_range(file_size) unless file_size.nil?

      if message.key?FILE_HOSTNAME
        to_druid[APPLICATION_ID_NAME] = "http"
      elsif message.key?EMAIL_SENDER
        to_druid[APPLICATION_ID_NAME] = "smtp"
      elsif message.key?"ftp_user"
        to_druid[APPLICATION_ID_NAME] = "ftp"
        to_druid["client_id"] = message["ftp_user"]
      elsif message.key?"smb_uid"
        to_druid[APPLICATION_ID_NAME] = "smb"
        to_druid["client_id"] = message["smb_uid"]
      end
      
      @aerospike_store.update_hash_times(timestamp, hash, "hash")

      hash_message = @aerospike_store.enrich_hash_scores(to_druid)
      url_message = @aerospike_store.enrich_url_scores(hash_message)
      ip_message = @aerospike_store.enrich_ip_scores(url_message)

      generated_events.push(LogStash::Event.new(ip_message))

      generated_events.each do |e|
        yield e
      end
    
    end
    event.cancel
  end  # def filter(event)
end # class LogStash::Filters::Ips
