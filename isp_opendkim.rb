#encoding=utf-8

# Copyright (C) 2017 Maurice Bleuel <mandrakey@bleuelmedia.com>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# use in crontab, for example like this:
# */5 * * * * root ruby /opt/isp_opendkim.rb

require 'mysql2'

# ==============================================================================
# CONFIGURATION

RX_PUBKEY = /(.+)\._domainkey\.(.+) IN TXT ".+p=(.+)"/
RX_PUBKEY_DB = /-----BEGIN PUBLIC KEY-----(.+)-----END PUBLIC KEY-----/
RX_PRIVKEY_DB = /-----BEGIN.*PRIVATE KEY-----(.+)-----END.*PRIVATE KEY-----/
RX_KEYTABLE_ENTRY = /(.+)\._domainkey\.(.+) (.+):(.+):(.+)/

CONFIG = {
  :verbose => true,
  :simulation => true,
  :db_host => '127.0.0.1',
  :db_user => 'dummy',
  :db_pass => 'doof',
  :db_base => 'dbispconfig',
  :db_port => 3306,
  :dkim_path => '/var/dkim',
  :dkim_uid => -1
}

# ==============================================================================
# CLASSES

class Key
  attr_accessor :public, :private, :domain, :selector, :type, :remove, :update

  def self.from_existing(domain, selector)
    k = Key.new(domain, selector, true)
  end

  def initialize(domain, selector, from_existing = false)
    @public = nil
    @private = nil
    @domain = domain
    @selector = selector
    @type = 'rsa'
    @remove = true
    @update = false

    if from_existing
      load_pubkey
      load_private
    end
  end

  private
  def load_pubkey
    keyfile = "#{CONFIG[:dkim_path]}/keys/#{@domain}/#{@selector}.txt"
    raise 'Key file does not exist' unless File.exist?(keyfile)

    data = File.read(keyfile).strip
    m = RX_PUBKEY.match data
    raise "Invalid public key data in #{keyfile}" if m == nil || m.size != 4

    raise "Keyfile selector (#{m[1]}) does not match key selector (#{@selector})" unless @selector == m[1]
    raise "Keyfile domain (#{m[2]} does not match key domain (#{@domain})" unless @domain == m[2]
    @public = m[3]
  end

  def load_private
    keyfile = "#{CONFIG[:dkim_path]}/keys/#{@domain}/#{@selector}.private"
    raise "Private key file does not exist: #{keyfile}" unless File.exist?(keyfile)

    @private = File.read keyfile
  end
end

# ==============================================================================
# FUNCTIONS

def load_keys_from(keyTableFile)
  raise "KeyTable file (#{keyTableFile}) does not exist" unless File.exist?(keyTableFile)

  keys = {}
  f = open(keyTableFile, 'r')
  f.each do |line|
    m = RX_KEYTABLE_ENTRY.match line
    if m == nil
      puts "WARN: Invalid KeyTable entry '#{@line}' skipped."
      next
    end

    selector = m[1]
    domain = m[2]
    k = Key.from_existing(domain, selector)
    keys["#{selector}.#{domain}"] = k
  end
  f.close

  keys
end

def load_active_keys(keys)
  db = Mysql2::Client.new(
    :host => CONFIG[:db_host],
    :username => CONFIG[:db_user],
    :password => CONFIG[:db_pass],
    :database => CONFIG[:db_base],
    :port => CONFIG[:db_port]
  )

  rows = db.query("SELECT domain, dkim, dkim_selector, dkim_private, dkim_public " +
    "FROM mail_domain WHERE dkim='y'")

  rows.each do |row|
    ident = "#{row['dkim_selector']}.#{row['domain']}"

    m = RX_PUBKEY_DB.match row['dkim_public'].gsub(/\r\n/, '')
    if m == nil
      puts "WARN: Failed to extract public key from db for #{ident}"
      next
    end
    pubkey = m[1]
    privkey = row['dkim_private']

    puts "Checking #{ident}..." if CONFIG[:verbose]
    if keys.has_key?(ident)
      k = keys[ident]
      k.remove = false
      if k.public != pubkey || k.private != privkey
        puts "Updating keys for #{ident}" if CONFIG[:verbose]
        k.update = true
        k.public = pubkey
        k.private = privkey
      end

    else
      puts "Adding keys for #{ident}" if CONFIG[:verbose]
      k = Key.new(row['domain'], row['dkim_selector'])
      k.public = pubkey
      k.private = privkey
      k.type = 'rsa'
      k.remove = false
      k.update = true
      keys[ident] = k
    end
  end
end

# ==============================================================================
# PROCESSING

keyTableFile = "#{CONFIG[:dkim_path]}/KeyTable"
signingTableFile = "#{CONFIG[:dkim_path]}/SigningTable"

keys = load_keys_from keyTableFile
load_active_keys keys

keyTable = ''
signingTable = ''

keys.each do |ident, k|
  keyDir = "#{CONFIG[:dkim_path]}/keys/#{k.domain}"
  pubkeyFile = "#{keyDir}/#{k.selector}.txt"
  privkeyFile = "#{keyDir}/#{k.selector}.private"

  if k.remove
    puts "Removing keys for #{ident}" if CONFIG[:verbose]
    unless CONFIG[:simulation]
      File.delete pubkeyFile
      File.delete privkeyFile
    else
      puts "[SIM] Deleting #{pubkeyFile}"
      puts "[SIM] Deleting #{privkeyFile}"
    end
  else
    if k.update

      unless CONFIG[:simulation]
        unless Dir.exist?(keyDir)
          Dir.mkdir keyDir
          File.chmod(0744, keyDir)
          File.chown(CONFIG[:dkim_uid], nil, keyDir)
        end
      else
        puts "[SIM] Create dir '#{keyDir}'" unless Dir.exist?(keyDir)
      end

      pubkeyFileContent = "#{k.selector}._domainkey.#{k.domain} IN TXT \"v=DKIM1; k=rsa; p=#{k.public}\" ; ----- DKIM key #{k.selector} for #{k.domain}"
      unless CONFIG[:simulation]
        File.write(pubkeyFile, pubkeyFileContent)
        File.write(privkeyFile, k.private)
        File.chmod(0644, pubkeyFile)
        File.chmod(0600, privkeyFile)
        File.chown(CONFIG[:dkim_uid], nil, pubkeyFile, privkeyFile)
      else
        puts "[SIM] '#{pubkeyFileContent}' > #{pubkeyFile}"
        puts "[SIM] '#{k.private}' > #{privkeyFile}"
      end
    end

    keyTable << "#{k.selector}._domainkey.#{k.domain} #{k.domain}:#{k.selector}:#{privkeyFile}\n"
    signingTable << "#{k.domain} #{k.selector}._domainkey.#{k.domain}\n"
  end
end

unless CONFIG[:simulation]
  File.write(keyTableFile, keyTable)
  File.write(signingTableFile, signingTable)
else
  puts "[SIM] Writing '#{keyTableFile}':\n#{keyTable}\n"
  puts "[SIM] Writing '#{signingTableFile}':\n#{signingTable}"
end
