#!/usr/bin/env ruby
# FROST — Forensic Recon & Security Toolkit
# Network Security Observer Edition

require 'socket'
require 'json'
require 'openssl'
require 'net/http'
require 'uri'
require 'digest'
require 'timeout'

########################################
# COLOR ENGINE
########################################
def c(text, color)
  colors = {
    green:  "\e[32m",
    yellow: "\e[33m",
    red:    "\e[31m",
    blue:   "\e[34m",
    gray:   "\e[90m",
    reset:  "\e[0m"
  }
  "#{colors[color]}#{text}#{colors[:reset]}"
end

def banner
  puts c("=========================================", :blue)
  puts c("  F R O S T  —  Network Security Observer ", :blue)
  puts c("=========================================", :blue)
end
def valid_ip?(ip)
  return true if ip =~ /\A\d{1,3}(\.\d{1,3}){3}\z/
  return true if ip.include?(":") && ip.count(":") >= 2
  false
end

########################################
# UTILITIES
########################################
def normalize_target(input)
  return input if input.start_with?("http")
  "https://#{input}"
end

def safe_filename(target)
  target.gsub(%r{https?://}, '')
        .gsub(/[^\w\-\.]/, '_')
end

########################################
# DNS RECON
########################################
def dns_recon(domain)
  puts c("[DNS] Resolving records…", :blue)
  records = {}
  ips = []

  %w[A AAAA NS MX TXT].each do |type|
    begin
      out = `nslookup -type=#{type} #{domain} 2>&1`
      cleaned = out.lines.reject { |l| l =~ /homerouter|fe80|Server:/i }.join.strip
      records[type] = cleaned.empty? ? nil : cleaned
      puts cleaned.empty? ? c("  #{type}: no data", :gray) : c("  #{type}: collected", :green)
      cleaned.scan(/\b\d{1,3}(?:\.\d{1,3}){3}\b|[a-f0-9:]{6,}/i) { |ip| ips << ip }
    rescue
      records[type] = nil
      puts c("  #{type}: failed", :red)
    end
  end

  [records, ips.uniq]
end

########################################
# PORT SCAN (SAFE)
########################################
def port_scan(ips)
  puts c("[PORTS] Checking common services…", :blue)
  ports = {}

  ips.each do |ip|
    next if ip.include?(":") # skip IPv6
    ports[ip] = []
    [80, 443].each do |p|
      begin
        Timeout.timeout(1) do
          s = TCPSocket.new(ip, p)
          s.close
          ports[ip] << "#{p}/tcp open"
          puts c("  #{ip}:#{p} open", :green)
        end
      rescue
        puts c("  #{ip}:#{p} closed/filtered", :gray)
      end
    end
  end
  ports
end

########################################
# TLS INSPECTION
########################################
def tls_inspect(domain)
  puts c("[TLS] Inspecting certificate…", :blue)
  ctx = OpenSSL::SSL::SSLContext.new
  sock = TCPSocket.new(domain, 443)
  ssl  = OpenSSL::SSL::SSLSocket.new(sock, ctx)
  ssl.hostname = domain
  ssl.connect

  cert = ssl.peer_cert
  ssl.close
  sock.close

  puts c("  Issuer: #{cert.issuer}", :green)
  puts c("  Expires: #{cert.not_after}", :green)

  {
    issuer: cert.issuer.to_s,
    expires: cert.not_after.to_s,
    subject: cert.subject.to_s
  }
rescue
  puts c("  TLS inspection blocked", :yellow)
  { error: "TLS unavailable or blocked" }
end

########################################
# HTTP HEADERS
########################################
def http_headers(url)
  puts c("[HTTP] Fetching headers…", :blue)
  uri = URI(url)
  res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") do |h|
    h.head(uri.request_uri.empty? ? "/" : uri.request_uri)
  end

  puts c("  Server: #{res['server']}", :green)
  {
    server: res['server'],
    headers: {
      hsts: res['strict-transport-security'],
      csp: res['content-security-policy'],
      xfo: res['x-frame-options'],
      xcto: res['x-content-type-options']
    }
  }
rescue
  puts c("  HTTP unreachable", :red)
  { error: "HTTP unreachable" }
end

########################################
# REACTION MONITORING (MINI ATTACK STYLE)
########################################
def reaction_monitor(url)
  puts c("[REACT] Observing server reactions…", :blue)
  uri = URI(url)
  tests = []

  [
    ["HEAD request", Net::HTTP::Head.new("/")],
    ["OPTIONS request", Net::HTTP::Options.new("/")],
    ["Malformed path", Net::HTTP::Get.new("/../../../../etc/passwd")],
    ["Bot UA", Net::HTTP::Get.new("/", { "User-Agent" => "curl/7.0" })]
  ].each do |name, req|
    begin
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") { |h| h.request(req) }
      hash = Digest::SHA1.hexdigest(res.body.to_s)
      puts c("  #{name}: #{res.code}", res.code.to_i >= 400 ? :yellow : :green)
      tests << {
        test: name,
        code: res.code,
        server: res['server'],
        body_hash: hash
      }
    rescue
      puts c("  #{name}: blocked", :red)
      tests << { test: name, error: "blocked" }
    end
  end
  tests
end

########################################
# SCORING
########################################
def score(results)
  score = 0
  notes = []

  score += 1 if results[:http][:headers][:csp].nil?
  score += 1 if results[:reaction].any? { |r| r[:code] == "200" && r[:test] == "Malformed path" }

  [score, notes]
end

########################################
# MAIN
########################################
abort("Usage: ruby FROST.rb <domain>") unless ARGV[0]

banner
target = normalize_target(ARGV[0])
domain = URI(target).host

results = {
  operation: "FROST",
  target: target,
  timestamp: Time.now.utc.to_s
}

dns, ips = dns_recon(domain)
results[:dns] = dns
results[:ips] = ips

results[:ports] = port_scan(ips)
results[:tls] = tls_inspect(domain)
results[:http] = http_headers(target)
results[:reaction] = reaction_monitor(target)

score, notes = score(results)
results[:defensive_score] = score
results[:notes] = notes

file = "FROST_#{safe_filename(domain)}_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
File.write(file, JSON.pretty_generate(results))

puts c("\n[✓] Scan complete", :green)
puts c("[✓] Defensive score: #{score}", score.zero? ? :green : :yellow)
puts c("[✓] Report saved to: #{file}", :blue)

def render_stored(results)
  puts c("\n========== STORED RESULTS (VISUAL) ==========", :blue)

  puts c("\n[Target]", :blue)
  puts c("  #{results[:target]}", :green)

  puts c("\n[DNS Records]", :blue)
  results[:dns].each do |type, data|
    if data.nil? || data.empty?
      puts c("  #{type}: none", :gray)
    elsif data.length < 40
      puts c("  #{type}: limited", :yellow)
    else
      puts c("  #{type}: present", :green)
    end
  end

  puts c("\n[IP Addresses]", :blue)
  results[:ips].each do |ip|
    if valid_ip?(ip)
      puts c("  #{ip}", :green)
    else
      puts c("  #{ip} (noise)", :gray)
    end
  end

  puts c("\n[Ports]", :blue)
  results[:ports].each do |ip, ports|
    if ports.empty?
      puts c("  #{ip}: none detected", :yellow)
    else
      ports.each do |p|
        puts c("  #{ip}: #{p}", :green)
      end
    end
  end

  puts c("\n[TLS]", :blue)
  if results[:tls][:error]
    puts c("  TLS blocked or hidden", :yellow)
  else
    exp = Time.parse(results[:tls][:expires]) rescue nil
    if exp && exp < Time.now + 30*24*3600
      puts c("  Certificate expires soon", :red)
    else
      puts c("  Certificate valid", :green)
    end
    puts c("  Issuer: #{results[:tls][:issuer]}", :green)
  end

  puts c("\n[HTTP Security Headers]", :blue)
  results[:http][:headers].each do |h, v|
    if v.nil?
      puts c("  #{h}: missing", :yellow)
    else
      puts c("  #{h}: present", :green)
    end
  end

  puts c("\n[Reaction Monitoring]", :blue)
  results[:reaction].each do |r|
    code = r[:code].to_i rescue 0
    color =
      if code >= 500
        :red
      elsif code >= 400
        :yellow
      elsif code == 200
        :green
      else
        :gray
      end
    puts c("  #{r[:test]} → #{r[:code]}", color)
  end

  puts c("\n[Defensive Score]", :blue)
  score = results[:defensive_score]
  puts c("  Score: #{score}", score == 0 ? :green : :yellow)

  puts c("============================================", :blue)
end

render_stored(results)

