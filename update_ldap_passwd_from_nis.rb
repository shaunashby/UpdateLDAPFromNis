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
require 'ldap/ldif'

# Generic Person class:
class Person
  def initialize(uid,password,dn)
    @uid=uid
    @password=password
    @dn=dn
  end

  attr_reader :uid,:password,:dn

  def to_s
    return sprintf("%-20s %-25s  %-20s\n",@uid,@password,@dn);
  end
end

class MyLDAP
  class People
    def initialize(hostname='ldap.isdc.unige.ch')
      begin
        @connection = LDAP::Conn.new(hostname, LDAP::LDAP_PORT)
        # Use protocol V3:
        @connection.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)        
      rescue LDAP::Error => err
        print($stderr," ERROR trying to create LDAP connection: #{err}")
        exit(1)
      end
      @entries = Hash::new()
    end

    attr_reader :entries

    def search(base_dn='ou=People,dc=isdc,dc=unige,dc=ch',filter='(objectclass=person)')
      @connection.simple_bind(nil,nil)
      begin
        @connection.search_ext2(base_dn,LDAP::LDAP_SCOPE_SUBTREE,filter) { |entry|
          if !entry.nil?
            password = nil
            # Entry might not have a userPassword attribute:
            if entry.has_key?('userPassword')
              password = entry['userPassword'].to_s
            end

            @entries[entry['uid'].to_s] = Person::new(entry['uid'].to_s,
                                                      password,
                                                      entry['dn'].to_s)
          end
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

    def find_entry_for_uid(uid)
      if @entries.has_key?(uid)
        return @entries[uid]
      end
      return nil
    end 
  end
end

class NIS
  class Password
    def initialize(passwd)
      @passwd=passwd
    end

    def to_s
      return "Crypt{#{@passwd}}"
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
            uid, password,uidNumber,gid,fullname,*rest = line.split(":")
            @entries << Person::new(uid,Password::new(password),fullname)
          end
        end  
      rescue => err
        print($stderr," ERROR trying to popen(#{query_command}): #{err}")
        exit(1)
      end      
    end
  end
end



#### Main ####
ldap_people = MyLDAP::People::new()
ldap_people.search()

# Somewhere to store modifications:
modifications=Array::new()

NIS::PasswordFile::new().entries.each do |nis_user|
  ldap_user = ldap_people.find_entry_for_uid(nis_user.uid)
  if !ldap_user.nil?
    if ldap_user.password.nil?
      puts "Creating LDAP password entry for UID #{nis_user.uid}" if $DEBUG
      # Add userPassword attribute:
      modifications << Hash[ ldap_user.dn, LDAP.mod(LDAP::LDAP_MOD_ADD, 'userPassword', [ "#{nis_user.password}" ]) ]
    else
      if ldap_user.password != nis_user.password
        puts "Synchronising NIS and LDAP password for UID #{nis_user.uid}" if $DEBUG
        # Modify the value of the userPassword attribute for this uid:
        modifications << Hash[ldap_user.dn,LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'userPassword', [ "#{nis_user.password}" ])]
      end
    end
  end
end

# Dump out the changes as LDIF:
modifications.each do |mod|
  mod.each_pair do |dn,ldap_mod|
    printf("%s\n",LDAP::LDIF.mods_to_ldif(dn,ldap_mod))
  end
end
