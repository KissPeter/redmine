# Redmine - project management software
# Copyright (C) 2006-2016  Jean-Philippe Lang
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

require 'net/ldap'
require 'net/ldap/dn'
require 'timeout'
require 'digest'
require 'base64'

class AuthSourceLdap < AuthSource
  validates_presence_of :host, :port, :attr_login
  validates_length_of :name, :host, :maximum => 60, :allow_nil => true
  validates_length_of :account, :account_password, :base_dn, :filter, :maximum => 255, :allow_blank => true
  validates_length_of :attr_login, :attr_firstname, :attr_lastname, :attr_mail, :maximum => 30, :allow_nil => true
  validates_numericality_of :port, :only_integer => true
  validates_numericality_of :timeout, :only_integer => true, :allow_blank => true
  validate :validate_filter

  before_validation :strip_ldap_attributes

  def initialize(attributes=nil, *args)
    super
    self.port = 389 if self.port == 0
  end

  def authenticate(login, password)
    return nil if login.blank? || password.blank?

    with_timeout do
      attrs = get_user_dn(login, password)
      if attrs && attrs[:dn] && authenticate_dn(attrs[:dn], password)
        logger.debug "Authentication successful for '#{login}'" if logger && logger.debug?
        return attrs.except(:dn)
      end
    end
  rescue Net::LDAP::LdapError => e
    raise AuthSourceException.new(e.message)
  end

  # test the connection to the LDAP
  def test_connection
    with_timeout do
      ldap_con = initialize_ldap_con(self.account, self.account_password)
      ldap_con.open { }
    end
  rescue Net::LDAP::LdapError => e
    raise AuthSourceException.new(e.message)
  end

  def auth_method_name
    "LDAP"
  end

  def allow_password_changes?
    self.class.allow_password_changes?
  end
  # Does this auth source backend allow password changes?
  def self.allow_password_changes?
    true
  end
  
  def encode_password(clear_password)
    chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
    salt = ''
    10.times { |i| salt << chars[rand(chars.size-1)] }
    logger.info "Encode as SSHA"
    return "{SSHA}"+Base64.encode64(Digest::SHA1.digest(clear_password+salt)+salt).chomp!
 end

  # change password
  def change_password(login,password,newPassword)
    begin
      attrs = get_user_dn(login, password)
      if attrs
        if self.account.blank? || self.account_password.blank?
          ldap_con = initialize_ldap_con(attrs[:dn], password)
        else
          ldap_con = initialize_ldap_con(self.account, self.account_password)
        end
        return ldap_con.replace_attribute attrs[:dn], :userPassword, encode_password(newPassword)
      end
     rescue
        return false
     end
    return false
  end
  
  # Lost password
  def lost_password(login,newPassword)
    begin
      attrs = get_user_dn_nopass(login)
      if attrs
        ldap_con = initialize_ldap_con(self.account, self.account_password)
        return ldap_con.replace_attribute attrs[:dn], :userPassword, encode_password(newPassword)
      end
     rescue
        return false
     end
    return false
  end
  
  
 # Returns true if this source can be searched for users
  def searchable?
    !account.to_s.include?("$login") && %w(login firstname lastname mail).all? {|a| send("attr_#{a}?")}
  end

  # Searches the source for users and returns an array of results
  def search(q)
    q = q.to_s.strip
    return [] unless searchable? && q.present?

    results = []
    search_filter = base_filter & Net::LDAP::Filter.begins(self.attr_login, q)
    ldap_con = initialize_ldap_con(self.account, self.account_password)
    ldap_con.search(:base => self.base_dn,
                    :filter => search_filter,
                    :attributes => ['dn', self.attr_login, self.attr_firstname, self.attr_lastname, self.attr_mail],
                    :size => 10) do |entry|
      attrs = get_user_attributes_from_ldap_entry(entry)
      attrs[:login] = AuthSourceLdap.get_attr(entry, self.attr_login)
      results << attrs
    end
    results
  rescue Net::LDAP::LdapError => e
    raise AuthSourceException.new(e.message)
  end

  private

  def with_timeout(&block)
    timeout = self.timeout
    timeout = 20 unless timeout && timeout > 0
    Timeout.timeout(timeout) do
      return yield
    end
  rescue Timeout::Error => e
    raise AuthSourceTimeoutException.new(e.message)
  end

  def ldap_filter
    if filter.present?
      Net::LDAP::Filter.construct(filter)
    end
  rescue Net::LDAP::LdapError
    nil
  end

  def base_filter
    filter = Net::LDAP::Filter.eq("objectClass", "*")
    if f = ldap_filter
      filter = filter & f
    end
    filter
  end

  def validate_filter
    if filter.present? && ldap_filter.nil?
      errors.add(:filter, :invalid)
    end
  end

  def strip_ldap_attributes
    [:attr_login, :attr_firstname, :attr_lastname, :attr_mail].each do |attr|
      write_attribute(attr, read_attribute(attr).strip) unless read_attribute(attr).nil?
    end
  end

  def initialize_ldap_con(ldap_user, ldap_password)
    options = { :host => self.host,
                :port => self.port,
                :encryption => (self.tls ? :simple_tls : nil)
              }
    options.merge!(:auth => { :method => :simple, :username => ldap_user, :password => ldap_password }) unless ldap_user.blank? && ldap_password.blank?
    Net::LDAP.new options
  end

  def get_user_attributes_from_ldap_entry(entry)
    {
     :dn => entry.dn,
     :firstname => AuthSourceLdap.get_attr(entry, self.attr_firstname),
     :lastname => AuthSourceLdap.get_attr(entry, self.attr_lastname),
     :mail => AuthSourceLdap.get_attr(entry, self.attr_mail),
     :auth_source_id => self.id
    }
  end

  # Return the attributes needed for the LDAP search.  It will only
  # include the user attributes if on-the-fly registration is enabled
  def search_attributes
    if onthefly_register?
      ['dn', self.attr_firstname, self.attr_lastname, self.attr_mail]
    else
      ['dn']
    end
  end

  # Check if a DN (user record) authenticates with the password
  def authenticate_dn(dn, password)
    if dn.present? && password.present?
      initialize_ldap_con(dn, password).bind
    end
  end

  # Get the user's dn and any attributes for them, given their login
  def get_user_dn(login, password)
    ldap_con = nil
    if self.account && self.account.include?("$login")
      ldap_con = initialize_ldap_con(self.account.sub("$login", Net::LDAP::DN.escape(login)), password)
    else
      ldap_con = initialize_ldap_con(self.account, self.account_password)
    end
    attrs = {}
    search_filter = base_filter & Net::LDAP::Filter.eq(self.attr_login, login)
    ldap_con.search( :base => self.base_dn,
                     :filter => search_filter,
                     :attributes=> search_attributes) do |entry|
      if onthefly_register?
        attrs = get_user_attributes_from_ldap_entry(entry)
      else
        attrs = {:dn => entry.dn}
      end
      logger.debug "DN found for #{login}: #{attrs[:dn]}" if logger && logger.debug?
    end
    attrs
  end
  
  # Get the user's dn and any attributes for them, given their login, without password
  def get_user_dn_nopass(login)
    ldap_con = nil
    ldap_con = initialize_ldap_con(self.account, self.account_password)
    attrs = {}
    search_filter = base_filter & Net::LDAP::Filter.eq(self.attr_login, login)
    ldap_con.search( :base => self.base_dn,
                     :filter => search_filter,
                     :attributes=> search_attributes) do |entry|
      if onthefly_register?
        attrs = get_user_attributes_from_ldap_entry(entry)
      else
        attrs = {:dn => entry.dn}
      end
      logger.debug "DN found for #{login}: #{attrs[:dn]}" if logger && logger.debug?
    end
    attrs
  end

  def self.get_attr(entry, attr_name)
    if !attr_name.blank?
      entry[attr_name].is_a?(Array) ? entry[attr_name].first : entry[attr_name]
    end
  end
end
