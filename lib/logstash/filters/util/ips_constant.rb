module IpsConstant

  # General
  SENSOR_NAME = "sensor_name" unless defined? SENSOR_NAME
  SENSOR_ID = "sensor_id" unless defined? SENSOR_ID
  DEPLOYMENT = "deployment" unless defined? DEPLOYMENT
  DEPLOYMENT_UUID = "deployment_uuid" unless defined? DEPLOYMENT_UUID
  NAMESPACE = "namespace" unless defined? NAMESPACE
  NAMESPACE_UUID = "namespace_uuid" unless defined? NAMESPACE_UUID
  HASH = "hash" unless defined? HASH
  URL = "url" unless defined? URL
  TYPE = "type" unless defined? TYPE
  TIMESTAMP = "timestamp" unless defined? TIMESTAMP
  PROBE_SCORE = "probe_score" unless defined? PROBE_SCORE
  CLIENT_MAC = "client_mac" unless defined? CLIENT_MAC 
  APPLICATION_ID_NAME = "application_id_name" unless defined? APPLICATION_ID_NAME
  SENSOR_UUID = "sensor_uuid" unless defined? SENSOR_UUID
  # Analysis
  LIST_TYPE = "list_type" unless defined? LIST_TYPE
  SCORE = "score" unless defined? SCORE
  IP_DIRECTION = "ip_direction" unless defined? IP_DIRECTION

  # MailGW
  FILES = "files" unless defined? FILES
  URLS = "urls" unless defined? URLS
  FILE_NAME = "file_name" unless defined? FILE_NAME
  EMAIL_SENDER = "email_sender" unless defined? EMAIL_SENDER
  EMAIL_DESTINATIONS = "email_destinations" unless defined? EMAIL_DESTINATIONS
  EMAIL_DESTINATION = "email_destination" unless defined? EMAIL_DESTINATION
  EMAIL_ID = "email_id" unless defined? EMAIL_ID
  SUBJECT = "subject" unless defined? SUBJECT

  ACTION = "action" unless defined? ACTION
  HEADERS = "headers" unless defined? HEADERS

  # ICAP
  HTTP_USER_AGENT_OS = "http_user_agent_os" unless defined? HTTP_USER_AGENT_OS
  PROXY_IP = "proxy_ip" unless defined? PROXY_IP

  # IPS
  SRC = "src" unless defined? SRC
  SHA256 = "sha256" unless defined? SHA256
  DST = "dst" unless defined? DST
  FILE_SIZE = "file_size" unless defined? FILE_SIZE
  FILE_URI = "file_uri" unless defined? FILE_URI
  FILE_HOSTNAME = "file_hostname" unless defined? FILE_HOSTNAME

  # ENDPOINT
  ENDPOINT_UUID = "endpoint_uuid" unless defined? ENDPOINT_UUID
end
