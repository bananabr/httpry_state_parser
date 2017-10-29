#!/usr/local/bin/ruby -w

#encoding: utf-8
require "date"
require "optparse"
require "thread"
require "logger"
require "parallel"

$stdout.sync = true
console_mutex = Mutex.new
state_table_mutex = Mutex.new
blacklist_mutex = Mutex.new

def purge(options, state_table, stale_time, mutex)
  begin
    while true
      length_before_purge = state_table.length
      mutex.synchronize do
        state_table = state_table.delete_if {|k, v| (v['stalestamp']+stale_time) <= Time.now.to_i }
      end
      length_after_purge = state_table.length
      if options["verbose"]
        puts "PURGE => Purging removed #{ length_before_purge - length_after_purge } entries from state table."
        puts "PURGE => State Table Entries: #{length_after_purge}"
      end
      sleep 5
    end
  rescue Exception => e
    puts "ERROR: #{e.message}"
  end
end

options = {}
options['logfile'] = STDOUT
options['fields'] = ['source-ip','source-port','dest-ip','dest-port','direction','status-code','method','host','request-uri', 'content-length']
stale_time = 30
blacklist = []

trap "SIGHUP" do
  Thread.new do
    blacklist_mutex.synchronize do
      puts "SIGHUP caught reloading blacklist"
      blacklist = []
      File.readlines(options['blacklist']).each{|line| blacklist << line.chomp()}
    end
  end.join
end

optparse = OptionParser.new do|opts|
        opts.banner = "Usage: httpry_state_parser.rb [options]"
        opts.separator ""
        opts.separator "Script options:"
        options["verbose"] = false
        opts.on( '-v','--verbose', 'Output more information' ) do
                options["verbose"] = true
        end
        opts.on("-lNAME", "--log-file=NAME", "Log file path") do |n|
                options['logfile'] = n
        end
        opts.on("-bFILEPATH", "--black-list=FILEPATH", "blacklist file path") do |f|
                options['blacklist'] = f
                File.readlines(f).each{|line| blacklist << line.chomp()}
        end
        opts.on("-fFIELDS", "--fields=FIELDS", "Comma separated list of fields as provided for httpry") do |f|
                options['fields'] = f.split(',')
        end
        opts.on( '-h', '--help', 'Display this screen' ) do
                puts opts
                exit
        end
end

state_table = {}
optparse.parse!
fields = options['fields']

logger = Logger.new(options['logfile'], 1000, 10240000)
logger.progname = 'httpry'
Thread.new{ purge(options, state_table, stale_time, state_table_mutex) }

Parallel.each( -> { STDIN.gets || Parallel::Stop }, in_threads: 8) do |line|
#while STDIN.gets
  begin
    log = {}
    #$_.split("\t").each_with_index do |v,i|
    line.chomp().split("\t").each_with_index do |v,i|
      log[fields[i]] = v
    end
  rescue
    next
  end

  _now = Time.now.to_i
  log['stalestamp'] = _now

  request_key = "#{log['source-ip']}-#{log['source-port']}-#{log['dest-ip']}-#{log['dest-port']}"
  response_key = "#{log['dest-ip']}-#{log['dest-port']}-#{log['source-ip']}-#{log['source-port']}"

  if log['direction'] == '>'
    state_table_mutex.synchronize do
      state_table[request_key] = log.dup
    end
  else
    state_table_mutex.synchronize do
      if state_table[response_key]
        entry = state_table[response_key]
        entry['status-code'] = log['status-code']
        entry['content-length'] = log['content-length']
        console_mutex.synchronize do
                blacklisted = false
                blacklist_mutex.synchronize do
                        blacklisted = (blacklist.reduce(0){|sum, e| /#{e}/ =~ entry['request-uri'] ? sum + 1 : sum }) > 0
                end
                if log['status-code'] == '200' and not blacklisted
                        logger.info(((fields).map{|f| entry[f] }).join("\t"))
                end
        end
        #state_table.delete(response_key)
      end
    end
  end

end