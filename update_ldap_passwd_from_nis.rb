#!/opt/local/bin/ruby
#____________________________________________________________________ 
# File: update_ldap_passwd_from_nis.rb
#____________________________________________________________________ 
#  
# Author: Shaun ASHBY <Shaun.Ashby@gmail.com>
# Update: 2010-06-29 16:47:38+0200
# Revision: $Id$ 
#
# Copyright: 2010 (C) Shaun ASHBY
#
#--------------------------------------------------------------------

require 'ldap'

class MyLDAP
  class People
    def initialize(hostname='ashby.isdc.unige.ch')
      @entries = Array::new
      begin
        @connection = LDAP::Conn.new(hostname, LDAP::LDAP_PORT)
        # Use protocol V3:
        @connection.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)        
      rescue LDAP::Error => err
        print($stderr," ERROR trying to create LDAP connection: #{err}")
        exit(1)
      end
    end
    
    attr_reader :entries
    
    def search(base_dn,filter='(objectclass=person)',attrs=['uid','userPassword','gid'])
      @connection.simple_bind(nil,nil)
      begin
        @connection.search(base_dn,LDAP::LDAP_SCOPE_SUBTREE,filter,attrs) { |entry|
          @entries << entry
        }
        @connection.unbind()
      rescue LDAP::ResultError => err
        print($stderr," ERROR trying to search DN #{base_dn}: #{err}")
        exit(1)
      rescue LDAP::Error => err
        print($stderr," ERROR in ldap_bind(): #{err}")
        exit(1)
      end
    end
  end
end

class NIS
  class PersonEntry
    def initialize(username,password)
      @username=username
      @password=password
    end
    
    attr_reader :username,:password
    
    def to_s
      return sprintf("%-40s  %-45s\n",@username,@password);
    end
  end
  
  class PasswordFile
    YPHOST='login'
    YPCAT='/usr/bin/ypcat'
    SSH='/usr/bin/ssh'
    
    def initialize()
      @entries = Array::new
      self.get_entries
    end
    
    attr_reader :entries
    
    def get_entries
      query_command=sprintf("%s %s %s passwd",SSH,YPHOST,YPCAT)
      begin
        IO::popen(query_command) do |f|
          while line = f.gets
            line.chomp!
            username, password, *rest = line.split(":")
            @entries << PersonEntry::new(username,password)
          end
        end  
      rescue => err
        print($stderr," ERROR trying to popen(#{query_command}): #{err}")
        exit(1)
      end      
    end
  end
end

# Main:
ldap_people = MyLDAP::People::new('ldap.isdc.unige.ch')
ldap_people.search('ou=People,dc=isdc,dc=unige,dc=ch')

for person in ldap_people.entries
  puts person.dn
end

nis_passwd_file = NIS::PasswordFile::new()

nis_passwd_file.entries.each do |nis_entry|
  puts nis_entry
end

