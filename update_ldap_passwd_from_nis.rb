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
    def initialize(hostname='ldap.isdc.unige.ch',dn='cn=auth_update,ou=Services,dc=ldap,dc=isdc,dc=unige,dc=ch',passwd='blahblah')
      begin
        @connection = LDAP::Conn.new(hostname, LDAP::LDAP_PORT)
        # Use protocol V3:
        @connection.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
        @connection.bind(dn,passwd)
      rescue LDAP::Error => err
        print($stderr," ERROR trying to create LDAP connection: #{err}")
        exit(1)
      end
      @entries = Hash::new()
      @additions = Array::new()
      @modifications = Array::new()
    end
    
    attr_reader :entries,:additions,:modifications
    
    def search(base_dn='ou=People,dc=isdc,dc=unige,dc=ch',filter='(objectclass=person)')
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
    
    def add_password_entry(person,passwd)
      puts "Going to create LDAP password entry for UID #{person.uid}" if $DEBUG
      @additions << Hash[person.dn, LDAP.mod(LDAP::LDAP_MOD_ADD, 'userPassword', [ passwd ])]
    end
    
    def modify_password_entry(person,passwd)
      puts "Synchronising NIS and LDAP password for UID #{person.uid}" if $DEBUG
      @modifications << Hash[person.dn,LDAP.mod(LDAP::LDAP_MOD_REPLACE, 'userPassword', [ passwd ])]
    end

    def commit_changes
      if @additions.size > 0
        puts "Accounts requiring userPassword attribute to be added:\n" if $DEBUG
        puts "\n"                                                       if $DEBUG
        begin
          @additions.each do |a|
            a.each_pair do |dn,ldap_mod|
              printf("%s\n",LDAP::LDIF.mods_to_ldif(dn,ldap_mod)) if $DEBUG
              @connection.add("#{dn}", [ ldap_mod ])
            end
          end
        rescue LDAP::ResultError => err
          print($stderr," ERROR during add: #{err}")
          exit(1)
        rescue LDAP::Error => err
          print($stderr," ERROR during add: #{err}")
          exit(1)
        end
      end
      
      if @modifications.size > 0
        puts "Accounts requiring userPassword value to be synchronized:\n" if $DEBUG
        puts "\n"                                                          if $DEBUG
        begin
          @modifications.each do |a|
            a.each_pair do |dn,ldap_mod|
              printf("%s\n",LDAP::LDIF.mods_to_ldif(dn,ldap_mod)) if $DEBUG
              @connection.add("#{dn}", [ ldap_mod ])
            end
          end
        rescue LDAP::ResultError => err
          print($stderr," ERROR during modify: #{err}")
          exit(1)
        rescue LDAP::Error => err
          print($stderr," ERROR during modify: #{err}")
          exit(1)
        end  
      end
      @connection.unbind()
    end
  end
end

class NIS
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
            @entries << Person::new(uid,"{CRYPT}#{password}",fullname)
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


ldap_people = MyLDAP::People::new(TEST_HOST,TEST_BIND_DN,TEST_PASS)
ldap_people.search(TEST_BASE_DN)

NIS::PasswordFile::new().entries.each do |nis_user|
  ldap_user = ldap_people.find_entry_for_uid(nis_user.uid)
  if !ldap_user.nil?
    if ldap_user.password.nil?
      # Add userPassword attribute:
      ldap_people.add_password_entry(ldap_user,nis_user.password)
    else
      if ldap_user.password != nis_user.password
        # Modify the value of the userPassword attribute for this uid:
        ldap_people.modify_password_entry(ldap_user,nis_user.password)
      end
    end
  end
end

ldap_people.commit_changes()
